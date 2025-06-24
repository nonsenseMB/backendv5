"""
Agent executor with streaming support.
"""
import asyncio
import uuid
from datetime import datetime
from typing import Any, AsyncIterator, Dict, List, Optional

from langchain_core.messages import HumanMessage
from langgraph.graph.graph import CompiledGraph

from src.agents.context import ExecutionContext, context_manager
from src.agents.events import (
    AgentEvent,
    AgentEventType,
    ErrorEvent,
    EventStream,
    LLMEvent
)
from src.agents.loader import AgentLoader, AgentState
from src.agents.exceptions import (
    AgentExecutionError,
    RateLimitExceededError
)
from src.core.auth.exceptions import InsufficientPermissionsError
from src.core.logging import get_logger
from src.infrastructure.database.models.agent import Agent
from src.infrastructure.database.models.conversation import Conversation
from src.infrastructure.database.models.user import User

logger = get_logger(__name__)


class StreamingResponse:
    """Response object for streaming agent execution."""
    
    def __init__(self, execution_id: str, events: AsyncIterator[AgentEvent]):
        self.execution_id = execution_id
        self.events = events
        self.final_output: Optional[str] = None
        self.error: Optional[str] = None
        self.metadata: Dict[str, Any] = {}
    
    async def collect_all(self) -> List[AgentEvent]:
        """Collect all events into a list."""
        events = []
        async for event in self.events:
            events.append(event)
        return events
    
    async def get_final_output(self) -> str:
        """Get the final output after consuming all events."""
        if self.final_output is not None:
            return self.final_output
        
        # Consume events to find final output
        async for event in self.events:
            if event.event_type == AgentEventType.AGENT_COMPLETE:
                self.final_output = event.metadata.get("final_output", "")
            elif event.event_type == AgentEventType.AGENT_ERROR:
                self.error = event.metadata.get("error_message", "Unknown error")
        
        if self.error:
            raise AgentExecutionError(self.error)
        
        return self.final_output or ""


class AgentExecutor:
    """Executor for running agents with streaming support."""
    
    def __init__(
        self,
        loader: AgentLoader,
        max_execution_time: int = 300,  # 5 minutes
        enable_streaming: bool = True
    ):
        self.loader = loader
        self.max_execution_time = max_execution_time
        self.enable_streaming = enable_streaming
        self.active_executions: Dict[str, ExecutionContext] = {}
    
    async def execute(
        self,
        agent: Agent,
        user: User,
        conversation: Conversation,
        message: str,
        context: Optional[Dict[str, Any]] = None,
        stream: bool = True
    ) -> StreamingResponse:
        """Execute an agent with streaming response."""
        execution_id = str(uuid.uuid4())
        
        # Create execution context
        exec_context = context_manager.create_context(
            agent=agent,
            user=user,
            conversation=conversation,
            tenant_id=agent.tenant_id,
            execution_id=execution_id,
            config=context or {}
        )
        
        # Store active execution
        self.active_executions[execution_id] = exec_context
        
        try:
            # Check permissions
            self._check_permissions(exec_context)
            
            # Check rate limits
            self._check_rate_limits(exec_context)
            
            # Load agent graph
            graph = self.loader.load_agent(agent)
            
            # Create initial state
            initial_state = self._create_initial_state(message, context)
            
            # Emit start event
            self._emit_start_event(exec_context)
            
            # Execute agent
            if stream and self.enable_streaming:
                # Stream execution
                events = self._stream_execution(
                    graph,
                    initial_state,
                    exec_context
                )
            else:
                # Non-streaming execution
                events = self._execute_sync(
                    graph,
                    initial_state,
                    exec_context
                )
            
            return StreamingResponse(execution_id, events)
            
        except Exception as e:
            # Emit error event
            self._emit_error_event(exec_context, str(e))
            
            # Clean up
            self.active_executions.pop(execution_id, None)
            context_manager.remove_context(execution_id)
            
            raise
    
    def _check_permissions(self, context: ExecutionContext):
        """Check if user has permission to execute agent."""
        agent = context.agent
        user = context.user
        
        # Check if agent is public
        if agent.is_public:
            return
        
        # Check if user is the creator
        if agent.created_by == user.id:
            return
        
        # Check if user has required role
        # This would typically check against user roles in the database
        user_roles = context.config.get("user_roles", [])
        if any(role in agent.allowed_roles for role in user_roles):
            return
        
        raise InsufficientPermissionsError(
            f"User {user.id} does not have permission to execute agent {agent.id}"
        )
    
    def _check_rate_limits(self, context: ExecutionContext):
        """Check rate limits for agent execution."""
        # Check user rate limit
        user_limit_key = f"user_{context.user.id}"
        user_limit = context.config.get("user_rate_limit", 100)
        
        if not context.check_rate_limit(user_limit_key, user_limit):
            raise RateLimitExceededError("User rate limit exceeded")
        
        # Check agent rate limit
        agent_limit_key = f"agent_{context.agent.id}"
        agent_limit = context.config.get("agent_rate_limit", 1000)
        
        if not context.check_rate_limit(agent_limit_key, agent_limit):
            raise RateLimitExceededError("Agent rate limit exceeded")
    
    def _create_initial_state(
        self,
        message: str,
        context: Optional[Dict[str, Any]] = None
    ) -> AgentState:
        """Create initial state for agent execution."""
        state = AgentState()
        
        # Add user message
        state.messages.append(HumanMessage(content=message))
        
        # Add context
        if context:
            state.context.update(context)
        
        return state
    
    def _emit_start_event(self, context: ExecutionContext):
        """Emit agent start event."""
        event = AgentEvent(
            event_type=AgentEventType.AGENT_START,
            timestamp=datetime.utcnow(),
            agent_id=context.agent.id,
            conversation_id=context.conversation.id,
            user_id=context.user.id,
            tenant_id=context.tenant_id,
            metadata={
                "agent_name": context.agent.name,
                "agent_type": context.agent.agent_type,
                "execution_id": context.execution_id
            }
        )
        context.emit_event(event)
    
    def _emit_complete_event(
        self,
        context: ExecutionContext,
        final_output: str
    ):
        """Emit agent complete event."""
        event = AgentEvent(
            event_type=AgentEventType.AGENT_COMPLETE,
            timestamp=datetime.utcnow(),
            agent_id=context.agent.id,
            conversation_id=context.conversation.id,
            user_id=context.user.id,
            tenant_id=context.tenant_id,
            metadata={
                "execution_id": context.execution_id,
                "final_output": final_output,
                "execution_time_ms": int(
                    (datetime.utcnow() - context.started_at).total_seconds() * 1000
                )
            }
        )
        context.emit_event(event)
    
    def _emit_error_event(
        self,
        context: ExecutionContext,
        error: str
    ):
        """Emit agent error event."""
        event = ErrorEvent(
            event_type=AgentEventType.AGENT_ERROR,
            timestamp=datetime.utcnow(),
            agent_id=context.agent.id,
            conversation_id=context.conversation.id,
            user_id=context.user.id,
            tenant_id=context.tenant_id,
            metadata={
                "execution_id": context.execution_id
            },
            error_type="AgentExecutionError",
            error_message=error,
            recoverable=False
        )
        context.emit_event(event)
    
    async def _stream_execution(
        self,
        graph: CompiledGraph,
        initial_state: AgentState,
        context: ExecutionContext
    ) -> AsyncIterator[AgentEvent]:
        """Stream agent execution events."""
        try:
            # Set up event collection
            collected_events = []
            
            def event_collector(event: AgentEvent):
                collected_events.append(event)
            
            context.event_stream.add_listener(event_collector)
            
            # Execute graph with timeout
            task = asyncio.create_task(
                self._run_graph_async(graph, initial_state, context)
            )
            
            # Stream events as they're collected
            last_index = 0
            while not task.done():
                # Yield new events
                while last_index < len(collected_events):
                    yield collected_events[last_index]
                    last_index += 1
                
                # Small delay to prevent busy waiting
                await asyncio.sleep(0.1)
            
            # Get final result
            final_state = await task
            
            # Yield any remaining events
            while last_index < len(collected_events):
                yield collected_events[last_index]
                last_index += 1
            
            # Extract final output
            final_output = self._extract_final_output(final_state)
            
            # Emit complete event
            self._emit_complete_event(context, final_output)
            
            # Yield the complete event
            if collected_events and collected_events[-1].event_type == AgentEventType.AGENT_COMPLETE:
                yield collected_events[-1]
            
        except asyncio.TimeoutError:
            error_msg = f"Agent execution timed out after {self.max_execution_time} seconds"
            self._emit_error_event(context, error_msg)
            raise AgentExecutionError(error_msg)
        
        except Exception as e:
            logger.error(f"Agent execution error: {str(e)}", exc_info=True)
            self._emit_error_event(context, str(e))
            raise
        
        finally:
            # Clean up
            context.event_stream.remove_listener(event_collector)
            self.active_executions.pop(context.execution_id, None)
            context_manager.remove_context(context.execution_id)
    
    async def _execute_sync(
        self,
        graph: CompiledGraph,
        initial_state: AgentState,
        context: ExecutionContext
    ) -> AsyncIterator[AgentEvent]:
        """Execute agent synchronously and return all events."""
        events = []
        
        def event_collector(event: AgentEvent):
            events.append(event)
        
        context.event_stream.add_listener(event_collector)
        
        try:
            # Execute graph
            final_state = await asyncio.wait_for(
                self._run_graph_async(graph, initial_state, context),
                timeout=self.max_execution_time
            )
            
            # Extract final output
            final_output = self._extract_final_output(final_state)
            
            # Emit complete event
            self._emit_complete_event(context, final_output)
            
        except asyncio.TimeoutError:
            error_msg = f"Agent execution timed out after {self.max_execution_time} seconds"
            self._emit_error_event(context, error_msg)
            raise AgentExecutionError(error_msg)
        
        except Exception as e:
            logger.error(f"Agent execution error: {str(e)}", exc_info=True)
            self._emit_error_event(context, str(e))
            raise
        
        finally:
            # Clean up
            context.event_stream.remove_listener(event_collector)
            self.active_executions.pop(context.execution_id, None)
            context_manager.remove_context(context.execution_id)
        
        # Return events as async iterator
        for event in events:
            yield event
    
    async def _run_graph_async(
        self,
        graph: CompiledGraph,
        initial_state: AgentState,
        context: ExecutionContext
    ) -> AgentState:
        """Run the graph asynchronously."""
        # LangGraph graphs can be invoked directly
        # They handle their own async execution
        
        # Set the execution context in state
        initial_state.context["_execution_context"] = context
        
        # Invoke the graph
        final_state = await graph.ainvoke(initial_state)
        
        return final_state
    
    def _extract_final_output(self, state: AgentState) -> str:
        """Extract final output from state."""
        # Try to get from context
        if hasattr(state, "context") and "final_output" in state.context:
            return str(state.context["final_output"])
        
        # Try to get last AI message
        if hasattr(state, "messages") and state.messages:
            for msg in reversed(state.messages):
                if hasattr(msg, "content") and msg.__class__.__name__ == "AIMessage":
                    return msg.content
        
        return ""
    
    async def cancel_execution(self, execution_id: str) -> bool:
        """Cancel an active execution."""
        if execution_id not in self.active_executions:
            return False
        
        context = self.active_executions[execution_id]
        
        # Emit cancellation event
        event = AgentEvent(
            event_type=AgentEventType.AGENT_ERROR,
            timestamp=datetime.utcnow(),
            agent_id=context.agent.id,
            conversation_id=context.conversation.id,
            user_id=context.user.id,
            tenant_id=context.tenant_id,
            metadata={
                "execution_id": execution_id,
                "error": "Execution cancelled by user"
            }
        )
        context.emit_event(event)
        
        # Clean up
        self.active_executions.pop(execution_id, None)
        context_manager.remove_context(execution_id)
        
        return True
    
    def get_active_executions(self) -> List[Dict[str, Any]]:
        """Get list of active executions."""
        return [
            {
                "execution_id": exec_id,
                "agent_id": str(context.agent.id),
                "agent_name": context.agent.name,
                "user_id": str(context.user.id),
                "started_at": context.started_at.isoformat(),
                "duration_seconds": (
                    datetime.utcnow() - context.started_at
                ).total_seconds()
            }
            for exec_id, context in self.active_executions.items()
        ]