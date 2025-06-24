"""
LangGraph node implementations for agent system.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from langchain_core.language_models import BaseLLM
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import Runnable

from src.agents.context import NodeContext
from src.agents.events import AgentEventType, NodeEvent
from src.core.logging import get_logger

logger = get_logger(__name__)


class BaseNode(Runnable):
    """Base class for all agent nodes."""
    
    def __init__(self, node_type: str, config: Dict[str, Any] = None):
        self.node_type = node_type
        self.config = config or {}
        self.node_id = self.config.get("id", f"{node_type}_{id(self)}")
        self.node_name = self.config.get("name", self.node_type.title())
    
    def create_context(self, execution_context, state) -> NodeContext:
        """Create node execution context."""
        return NodeContext(
            execution_context=execution_context,
            node_id=self.node_id,
            node_type=self.node_type,
            node_name=self.node_name,
            input_data=state.to_dict() if hasattr(state, "to_dict") else {}
        )
    
    def emit_start_event(self, context: NodeContext):
        """Emit node start event."""
        event = NodeEvent(
            event_type=AgentEventType.NODE_START,
            timestamp=datetime.utcnow(),
            agent_id=context.execution_context.agent.id,
            conversation_id=context.execution_context.conversation.id,
            user_id=context.execution_context.user.id,
            tenant_id=context.execution_context.tenant_id,
            metadata={},
            node_id=context.node_id,
            node_type=context.node_type,
            node_name=context.node_name,
            input_data=context.input_data
        )
        context.emit_event(event)
    
    def emit_complete_event(self, context: NodeContext):
        """Emit node complete event."""
        event = NodeEvent(
            event_type=AgentEventType.NODE_COMPLETE,
            timestamp=datetime.utcnow(),
            agent_id=context.execution_context.agent.id,
            conversation_id=context.execution_context.conversation.id,
            user_id=context.execution_context.user.id,
            tenant_id=context.execution_context.tenant_id,
            metadata={},
            node_id=context.node_id,
            node_type=context.node_type,
            node_name=context.node_name,
            output_data=context.output_data,
            execution_time_ms=context.execution_time_ms
        )
        context.emit_event(event)
    
    def emit_error_event(self, context: NodeContext, error: str):
        """Emit node error event."""
        event = NodeEvent(
            event_type=AgentEventType.NODE_ERROR,
            timestamp=datetime.utcnow(),
            agent_id=context.execution_context.agent.id,
            conversation_id=context.execution_context.conversation.id,
            user_id=context.execution_context.user.id,
            tenant_id=context.execution_context.tenant_id,
            metadata={},
            node_id=context.node_id,
            node_type=context.node_type,
            node_name=context.node_name,
            error=error,
            execution_time_ms=context.execution_time_ms
        )
        context.emit_event(event)


class InputNode(BaseNode):
    """Node for processing user input."""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("input", config)
    
    def invoke(self, state: Any, config: Dict[str, Any] = None) -> Any:
        """Process user input."""
        # In a real implementation, this would get execution context
        # For now, we'll just process the state
        
        logger.info(f"InputNode processing state", node_id=self.node_id)
        
        # Extract user message from state
        if hasattr(state, "messages") and state.messages:
            last_message = state.messages[-1]
            if isinstance(last_message, HumanMessage):
                state.context["user_input"] = last_message.content
        
        # Update current node
        state.current_node = self.node_id
        state.execution_path.append(self.node_id)
        
        return state


class LLMNode(BaseNode):
    """Node for LLM interaction."""
    
    def __init__(
        self,
        llm: BaseLLM,
        system_prompt: Optional[str] = None,
        config: Dict[str, Any] = None
    ):
        super().__init__("llm", config)
        self.llm = llm
        self.system_prompt = system_prompt or "You are a helpful AI assistant."
        self.temperature = self.config.get("temperature", 0.7)
        self.max_tokens = self.config.get("max_tokens", 500)
    
    def invoke(self, state: Any, config: Dict[str, Any] = None) -> Any:
        """Generate LLM response."""
        logger.info(f"LLMNode generating response", node_id=self.node_id)
        
        try:
            # Build messages
            messages = []
            
            # Add system prompt
            messages.append(SystemMessage(content=self.system_prompt))
            
            # Add context if available
            if hasattr(state, "context") and "context_prompt" in state.context:
                messages.append(SystemMessage(content=state.context["context_prompt"]))
            
            # Add conversation history
            if hasattr(state, "messages"):
                messages.extend(state.messages)
            
            # Generate response
            response = self.llm.invoke(
                messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens
            )
            
            # Add response to state
            if hasattr(state, "messages"):
                state.messages.append(AIMessage(content=response.content))
            
            # Update context
            state.context["llm_response"] = response.content
            state.current_node = self.node_id
            state.execution_path.append(self.node_id)
            
        except Exception as e:
            logger.error(f"LLM node error: {str(e)}", node_id=self.node_id)
            state.error = str(e)
        
        return state


class ConditionNode(BaseNode):
    """Node for conditional branching."""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("condition", config)
        self.condition_type = self.config.get("type", "simple")
    
    def invoke(self, state: Any, config: Dict[str, Any] = None) -> Any:
        """Evaluate condition."""
        logger.info(
            f"ConditionNode evaluating",
            node_id=self.node_id,
            condition_type=self.condition_type
        )
        
        # The actual condition evaluation is handled by the graph
        # This node just updates the state
        state.current_node = self.node_id
        state.execution_path.append(self.node_id)
        
        return state


class MemoryNode(BaseNode):
    """Node for memory operations."""
    
    def __init__(self, agent_id: UUID, config: Dict[str, Any] = None):
        super().__init__("memory", config)
        self.agent_id = agent_id
        self.operation = self.config.get("operation", "query")  # query, update, clear
        self.memory_type = self.config.get("memory_type", "short_term")  # short_term, long_term
    
    def invoke(self, state: Any, config: Dict[str, Any] = None) -> Any:
        """Perform memory operation."""
        logger.info(
            f"MemoryNode performing {self.operation}",
            node_id=self.node_id,
            memory_type=self.memory_type
        )
        
        try:
            if self.operation == "query":
                # Query memory based on context
                query = state.context.get("memory_query", "")
                # In a real implementation, this would query the memory store
                state.memory["query_results"] = []
                
            elif self.operation == "update":
                # Update memory with new information
                content = state.context.get("memory_content", "")
                if content:
                    if self.memory_type == "short_term":
                        if "short_term" not in state.memory:
                            state.memory["short_term"] = []
                        state.memory["short_term"].append({
                            "content": content,
                            "timestamp": datetime.utcnow().isoformat()
                        })
                    # In a real implementation, this would persist to database
                
            elif self.operation == "clear":
                # Clear specified memory
                if self.memory_type in state.memory:
                    state.memory[self.memory_type] = []
            
            state.current_node = self.node_id
            state.execution_path.append(self.node_id)
            
        except Exception as e:
            logger.error(f"Memory node error: {str(e)}", node_id=self.node_id)
            state.error = str(e)
        
        return state


class OutputNode(BaseNode):
    """Node for formatting final output."""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("output", config)
        self.output_format = self.config.get("format", "text")  # text, json, markdown
    
    def invoke(self, state: Any, config: Dict[str, Any] = None) -> Any:
        """Format and prepare output."""
        logger.info(f"OutputNode formatting output", node_id=self.node_id)
        
        try:
            # Extract the final response
            final_response = ""
            
            # Get LLM response if available
            if hasattr(state, "context") and "llm_response" in state.context:
                final_response = state.context["llm_response"]
            elif hasattr(state, "messages") and state.messages:
                # Get last AI message
                for msg in reversed(state.messages):
                    if isinstance(msg, AIMessage):
                        final_response = msg.content
                        break
            
            # Format based on output type
            if self.output_format == "json":
                state.context["final_output"] = {
                    "response": final_response,
                    "execution_path": state.execution_path,
                    "tools_used": list(state.tools_output.keys()) if hasattr(state, "tools_output") else []
                }
            elif self.output_format == "markdown":
                state.context["final_output"] = f"**Response:**\n\n{final_response}"
            else:
                state.context["final_output"] = final_response
            
            state.current_node = self.node_id
            state.execution_path.append(self.node_id)
            
        except Exception as e:
            logger.error(f"Output node error: {str(e)}", node_id=self.node_id)
            state.error = str(e)
        
        return state


class CustomNode(BaseNode):
    """Base class for custom nodes."""
    
    def __init__(self, node_type: str, handler: callable, config: Dict[str, Any] = None):
        super().__init__(node_type, config)
        self.handler = handler
    
    def invoke(self, state: Any, config: Dict[str, Any] = None) -> Any:
        """Execute custom handler."""
        logger.info(f"CustomNode executing handler", node_id=self.node_id)
        
        try:
            # Call the custom handler
            result = self.handler(state, self.config)
            
            # Update state
            state.current_node = self.node_id
            state.execution_path.append(self.node_id)
            
            # Merge result if it's a dict
            if isinstance(result, dict):
                state.context.update(result)
            
        except Exception as e:
            logger.error(f"Custom node error: {str(e)}", node_id=self.node_id)
            state.error = str(e)
        
        return state