"""
Agent execution context management.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from src.agents.events import AgentEvent, EventStream
from src.core.context import get_request_context
from src.infrastructure.database.models.agent import Agent, AgentMemory
from src.infrastructure.database.models.conversation import Conversation
from src.infrastructure.database.models.tool import Tool
from src.infrastructure.database.models.user import User


@dataclass
class MemoryContext:
    """Context for agent memory access."""
    
    short_term_memories: List[Dict[str, Any]] = field(default_factory=list)
    long_term_memories: List[AgentMemory] = field(default_factory=list)
    conversation_history: List[Dict[str, Any]] = field(default_factory=list)
    
    def add_short_term_memory(self, content: str, metadata: Dict[str, Any] = None):
        """Add a short-term memory."""
        self.short_term_memories.append({
            "content": content,
            "timestamp": datetime.utcnow(),
            "metadata": metadata or {}
        })
    
    def get_recent_memories(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent memories from both short and long term."""
        all_memories = []
        
        # Add short-term memories
        all_memories.extend(self.short_term_memories[-limit:])
        
        # Add long-term memories
        for memory in self.long_term_memories[:limit]:
            all_memories.append({
                "content": memory.content,
                "timestamp": memory.created_at,
                "metadata": memory.extra_data,
                "type": memory.memory_type,
                "confidence": memory.confidence
            })
        
        # Sort by timestamp and return
        all_memories.sort(key=lambda x: x["timestamp"], reverse=True)
        return all_memories[:limit]


@dataclass
class ExecutionContext:
    """Context for agent execution."""
    
    # Core identifiers
    agent: Agent
    user: User
    conversation: Conversation
    tenant_id: UUID
    
    # Execution metadata
    execution_id: str
    started_at: datetime = field(default_factory=datetime.utcnow)
    
    # State management
    current_state: Dict[str, Any] = field(default_factory=dict)
    execution_history: List[Dict[str, Any]] = field(default_factory=list)
    
    # Memory context
    memory: MemoryContext = field(default_factory=MemoryContext)
    
    # Tool access
    available_tools: List[Tool] = field(default_factory=list)
    tool_executions: List[Dict[str, Any]] = field(default_factory=list)
    
    # Event streaming
    event_stream: EventStream = field(default_factory=EventStream)
    
    # Configuration
    config: Dict[str, Any] = field(default_factory=dict)
    
    # Security
    permissions: List[str] = field(default_factory=list)
    rate_limits: Dict[str, int] = field(default_factory=dict)
    
    def __post_init__(self):
        """Initialize context with request context if available."""
        # Try to get request context
        try:
            request_ctx = get_request_context()
            if request_ctx:
                self.tenant_id = request_ctx.tenant_id
                self.config["request_id"] = request_ctx.request_id
        except Exception:
            pass
    
    def update_state(self, key: str, value: Any):
        """Update execution state."""
        self.current_state[key] = value
        self.execution_history.append({
            "timestamp": datetime.utcnow(),
            "action": "state_update",
            "key": key,
            "value": value
        })
    
    def get_state(self, key: str, default: Any = None) -> Any:
        """Get state value."""
        return self.current_state.get(key, default)
    
    def emit_event(self, event: AgentEvent):
        """Emit an event to the stream."""
        self.event_stream.emit(event)
    
    def record_tool_execution(self, tool_id: UUID, input_data: Dict[str, Any], output_data: Dict[str, Any] = None):
        """Record a tool execution."""
        execution = {
            "tool_id": tool_id,
            "input_data": input_data,
            "output_data": output_data,
            "timestamp": datetime.utcnow()
        }
        self.tool_executions.append(execution)
    
    def has_permission(self, permission: str) -> bool:
        """Check if context has a specific permission."""
        return permission in self.permissions
    
    def check_rate_limit(self, key: str, limit: int) -> bool:
        """Check if rate limit is exceeded."""
        current = self.rate_limits.get(key, 0)
        if current >= limit:
            return False
        self.rate_limits[key] = current + 1
        return True
    
    def get_conversation_summary(self) -> str:
        """Get a summary of the conversation history."""
        if not self.memory.conversation_history:
            return "No conversation history available."
        
        # Get last 10 messages
        recent_messages = self.memory.conversation_history[-10:]
        summary_parts = []
        
        for msg in recent_messages:
            role = msg.get("role", "unknown")
            content = msg.get("content", "")
            # Truncate long messages
            if len(content) > 200:
                content = content[:200] + "..."
            summary_parts.append(f"{role}: {content}")
        
        return "\n".join(summary_parts)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary for serialization."""
        return {
            "agent_id": str(self.agent.id),
            "agent_name": self.agent.name,
            "user_id": str(self.user.id),
            "conversation_id": str(self.conversation.id),
            "tenant_id": str(self.tenant_id),
            "execution_id": self.execution_id,
            "started_at": self.started_at.isoformat(),
            "current_state": self.current_state,
            "tool_executions_count": len(self.tool_executions),
            "memory_count": len(self.memory.short_term_memories) + len(self.memory.long_term_memories),
            "permissions": self.permissions
        }


@dataclass
class NodeContext:
    """Context for a specific node execution within the agent graph."""
    
    # Parent context
    execution_context: ExecutionContext
    
    # Node information
    node_id: str
    node_type: str  # input, llm, tool, condition, memory, output
    node_name: str
    
    # Node-specific state
    input_data: Dict[str, Any] = field(default_factory=dict)
    output_data: Dict[str, Any] = field(default_factory=dict)
    local_state: Dict[str, Any] = field(default_factory=dict)
    
    # Execution tracking
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    
    def complete(self, output_data: Dict[str, Any] = None):
        """Mark node as completed."""
        self.completed_at = datetime.utcnow()
        if output_data:
            self.output_data = output_data
    
    def fail(self, error: str):
        """Mark node as failed."""
        self.completed_at = datetime.utcnow()
        self.error = error
    
    @property
    def execution_time_ms(self) -> Optional[int]:
        """Get execution time in milliseconds."""
        if self.completed_at and self.started_at:
            return int((self.completed_at - self.started_at).total_seconds() * 1000)
        return None
    
    def emit_event(self, event: AgentEvent):
        """Emit event through parent context."""
        self.execution_context.emit_event(event)
    
    def update_state(self, key: str, value: Any):
        """Update local node state."""
        self.local_state[key] = value
    
    def get_state(self, key: str, default: Any = None) -> Any:
        """Get local state value."""
        return self.local_state.get(key, default)
    
    def get_global_state(self, key: str, default: Any = None) -> Any:
        """Get global state from execution context."""
        return self.execution_context.get_state(key, default)
    
    def update_global_state(self, key: str, value: Any):
        """Update global execution state."""
        self.execution_context.update_state(key, value)


class ContextManager:
    """Manager for agent execution contexts."""
    
    def __init__(self):
        self.active_contexts: Dict[str, ExecutionContext] = {}
    
    def create_context(
        self,
        agent: Agent,
        user: User,
        conversation: Conversation,
        tenant_id: UUID,
        execution_id: str,
        config: Dict[str, Any] = None
    ) -> ExecutionContext:
        """Create a new execution context."""
        context = ExecutionContext(
            agent=agent,
            user=user,
            conversation=conversation,
            tenant_id=tenant_id,
            execution_id=execution_id,
            config=config or {}
        )
        
        # Store active context
        self.active_contexts[execution_id] = context
        
        return context
    
    def get_context(self, execution_id: str) -> Optional[ExecutionContext]:
        """Get an active context by execution ID."""
        return self.active_contexts.get(execution_id)
    
    def remove_context(self, execution_id: str):
        """Remove a context when execution is complete."""
        if execution_id in self.active_contexts:
            del self.active_contexts[execution_id]
    
    def get_active_contexts(self) -> List[ExecutionContext]:
        """Get all active contexts."""
        return list(self.active_contexts.values())
    
    def cleanup_stale_contexts(self, max_age_seconds: int = 3600):
        """Clean up contexts older than max age."""
        now = datetime.utcnow()
        stale_ids = []
        
        for exec_id, context in self.active_contexts.items():
            age = (now - context.started_at).total_seconds()
            if age > max_age_seconds:
                stale_ids.append(exec_id)
        
        for exec_id in stale_ids:
            self.remove_context(exec_id)
        
        return len(stale_ids)


# Global context manager instance
context_manager = ContextManager()