"""
Agent event types for streaming and monitoring.
"""
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID


class AgentEventType(Enum):
    """Types of events emitted during agent execution."""
    
    # Lifecycle events
    AGENT_START = "agent_start"
    AGENT_COMPLETE = "agent_complete"
    AGENT_ERROR = "agent_error"
    
    # LLM events
    LLM_START = "llm_start"
    LLM_TOKEN = "llm_token"
    LLM_COMPLETE = "llm_complete"
    LLM_ERROR = "llm_error"
    
    # Tool events
    TOOL_START = "tool_start"
    TOOL_COMPLETE = "tool_complete"
    TOOL_ERROR = "tool_error"
    
    # Memory events
    MEMORY_QUERY = "memory_query"
    MEMORY_UPDATE = "memory_update"
    MEMORY_ERROR = "memory_error"
    
    # Node events (LangGraph specific)
    NODE_START = "node_start"
    NODE_COMPLETE = "node_complete"
    NODE_ERROR = "node_error"
    
    # Routing events
    CONDITION_EVALUATED = "condition_evaluated"
    ROUTE_SELECTED = "route_selected"


@dataclass
class AgentEvent:
    """Base class for all agent events."""
    
    event_type: AgentEventType
    timestamp: datetime
    agent_id: UUID
    conversation_id: UUID
    user_id: UUID
    tenant_id: UUID
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for streaming."""
        return {
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "agent_id": str(self.agent_id),
            "conversation_id": str(self.conversation_id),
            "user_id": str(self.user_id),
            "tenant_id": str(self.tenant_id),
            "metadata": self.metadata
        }


@dataclass
class LLMEvent(AgentEvent):
    """Event for LLM interactions."""
    
    model: str
    provider: str
    prompt: Optional[str] = None
    completion: Optional[str] = None
    token: Optional[str] = None
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    total_tokens: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert LLM event to dictionary."""
        data = super().to_dict()
        data.update({
            "model": self.model,
            "provider": self.provider,
            "prompt": self.prompt,
            "completion": self.completion,
            "token": self.token,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens
        })
        return data


@dataclass
class ToolEvent(AgentEvent):
    """Event for tool executions."""
    
    tool_id: UUID
    tool_name: str
    input_data: Dict[str, Any]
    output_data: Optional[Dict[str, Any]] = None
    execution_time_ms: Optional[int] = None
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert tool event to dictionary."""
        data = super().to_dict()
        data.update({
            "tool_id": str(self.tool_id),
            "tool_name": self.tool_name,
            "input_data": self.input_data,
            "output_data": self.output_data,
            "execution_time_ms": self.execution_time_ms,
            "error": self.error
        })
        return data


@dataclass
class MemoryEvent(AgentEvent):
    """Event for memory operations."""
    
    memory_type: str  # stm, ltm, vector
    operation: str  # query, update, delete
    query: Optional[str] = None
    results: Optional[List[Dict[str, Any]]] = None
    update_data: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert memory event to dictionary."""
        data = super().to_dict()
        data.update({
            "memory_type": self.memory_type,
            "operation": self.operation,
            "query": self.query,
            "results": self.results,
            "update_data": self.update_data
        })
        return data


@dataclass
class NodeEvent(AgentEvent):
    """Event for LangGraph node execution."""
    
    node_id: str
    node_type: str  # input, llm, tool, condition, memory, output
    node_name: str
    input_data: Optional[Dict[str, Any]] = None
    output_data: Optional[Dict[str, Any]] = None
    execution_time_ms: Optional[int] = None
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert node event to dictionary."""
        data = super().to_dict()
        data.update({
            "node_id": self.node_id,
            "node_type": self.node_type,
            "node_name": self.node_name,
            "input_data": self.input_data,
            "output_data": self.output_data,
            "execution_time_ms": self.execution_time_ms,
            "error": self.error
        })
        return data


@dataclass
class ErrorEvent(AgentEvent):
    """Event for errors during execution."""
    
    error_type: str
    error_message: str
    error_details: Optional[Dict[str, Any]] = None
    stack_trace: Optional[str] = None
    recoverable: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error event to dictionary."""
        data = super().to_dict()
        data.update({
            "error_type": self.error_type,
            "error_message": self.error_message,
            "error_details": self.error_details,
            "stack_trace": self.stack_trace,
            "recoverable": self.recoverable
        })
        return data


class EventStream:
    """Helper class for event streaming."""
    
    def __init__(self):
        self.events: List[AgentEvent] = []
        self.listeners: List[Any] = []
    
    def emit(self, event: AgentEvent):
        """Emit an event to all listeners."""
        self.events.append(event)
        for listener in self.listeners:
            try:
                listener(event)
            except Exception:
                # Log error but don't fail
                pass
    
    def add_listener(self, listener):
        """Add an event listener."""
        self.listeners.append(listener)
    
    def remove_listener(self, listener):
        """Remove an event listener."""
        if listener in self.listeners:
            self.listeners.remove(listener)
    
    def get_events(self, event_type: Optional[AgentEventType] = None) -> List[AgentEvent]:
        """Get events, optionally filtered by type."""
        if event_type:
            return [e for e in self.events if e.event_type == event_type]
        return self.events.copy()