"""
Agent API schemas.
"""
import html
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class AgentCreateRequest(BaseModel):
    """Request schema for creating an agent."""
    
    name: str = Field(..., min_length=3, max_length=100, pattern="^[a-z0-9_-]+$")
    display_name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    agent_type: str = Field("general", pattern="^(general|specialist|coordinator|team)$")
    specialization: Optional[str] = Field(None, max_length=100)
    graph_definition: Dict[str, Any]
    system_prompt: Optional[str] = Field(None, max_length=2000)
    capabilities: List[str] = Field(default_factory=list)
    tool_ids: List[UUID] = Field(default_factory=list)
    is_public: bool = Field(False)
    team_id: Optional[UUID] = None
    temperature: float = Field(0.7, ge=0.0, le=2.0)
    
    @field_validator("display_name", "description", "system_prompt")
    @classmethod
    def sanitize_html(cls, v: str | None) -> str | None:
        """Sanitize HTML to prevent XSS."""
        if v is None:
            return v
        return html.escape(v)
    
    @field_validator("capabilities")
    @classmethod
    def validate_capabilities(cls, v: List[str]) -> List[str]:
        """Validate capabilities."""
        allowed = {
            "web_search", "code_execution", "file_access", "memory_access",
            "tool_usage", "agent_coordination", "task_breakdown"
        }
        invalid = set(v) - allowed
        if invalid:
            raise ValueError(f"Invalid capabilities: {invalid}")
        return v


class AgentUpdateRequest(BaseModel):
    """Request schema for updating an agent."""
    
    display_name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    graph_definition: Optional[Dict[str, Any]] = None
    system_prompt: Optional[str] = Field(None, max_length=2000)
    capabilities: Optional[List[str]] = None
    tool_ids: Optional[List[UUID]] = None
    is_active: Optional[bool] = None
    is_public: Optional[bool] = None
    temperature: Optional[float] = Field(None, ge=0.0, le=2.0)
    
    @field_validator("display_name", "description", "system_prompt")
    @classmethod
    def sanitize_html(cls, v: str | None) -> str | None:
        """Sanitize HTML to prevent XSS."""
        if v is None:
            return v
        return html.escape(v)


class AgentResponse(BaseModel):
    """Response schema for agent."""
    
    id: UUID
    name: str
    display_name: str
    description: Optional[str]
    avatar_url: Optional[str]
    agent_type: str
    specialization: Optional[str]
    capabilities: List[str]
    tool_ids: List[UUID]
    is_public: bool
    is_active: bool
    team_id: Optional[UUID]
    created_by: UUID
    created_at: datetime
    updated_at: datetime
    
    # Metrics
    total_conversations: int
    satisfaction_score: float
    avg_response_time_ms: int
    
    class Config:
        from_attributes = True


class AgentDetailResponse(AgentResponse):
    """Detailed response schema for agent including graph definition."""
    
    graph_definition: Dict[str, Any]
    system_prompt: Optional[str]
    temperature: float
    model_preferences: Dict[str, Any]
    allowed_roles: List[str]
    tags: List[str]
    
    class Config:
        from_attributes = True


class AgentListResponse(BaseModel):
    """Response schema for agent list."""
    
    agents: List[AgentResponse]
    total: int
    limit: int
    offset: int


class AgentExecuteRequest(BaseModel):
    """Request schema for executing an agent."""
    
    message: str = Field(..., min_length=1, max_length=5000)
    context: Optional[Dict[str, Any]] = Field(default_factory=dict)
    stream: bool = Field(True)
    
    @field_validator("message")
    @classmethod
    def sanitize_message(cls, v: str) -> str:
        """Sanitize message."""
        return html.escape(v)


class AgentExecuteResponse(BaseModel):
    """Response schema for agent execution."""
    
    execution_id: str
    status: str = "streaming"
    message: str = "Agent execution started"


class AgentEventResponse(BaseModel):
    """Response schema for agent events (for SSE streaming)."""
    
    event_type: str
    timestamp: datetime
    agent_id: UUID
    metadata: Dict[str, Any]
    
    # Optional fields based on event type
    content: Optional[str] = None
    token: Optional[str] = None
    error: Optional[str] = None
    
    class Config:
        from_attributes = True


class AgentMemoryRequest(BaseModel):
    """Request schema for adding agent memory."""
    
    memory_type: str = Field(..., pattern="^(learning|pattern|feedback|optimization)$")
    content: str = Field(..., min_length=1, max_length=2000)
    conversation_id: Optional[UUID] = None
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    source: str = Field("user_feedback", pattern="^(user_feedback|self_learning|system)$")
    
    @field_validator("content")
    @classmethod
    def sanitize_content(cls, v: str) -> str:
        """Sanitize content."""
        return html.escape(v)


class AgentMemoryResponse(BaseModel):
    """Response schema for agent memory."""
    
    id: UUID
    agent_id: UUID
    memory_type: str
    content: str
    confidence: float
    usefulness_score: float
    application_count: int
    source: str
    is_active: bool
    created_at: datetime
    last_applied_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class AgentValidationRequest(BaseModel):
    """Request schema for validating agent definition."""
    
    graph_definition: Dict[str, Any]


class AgentValidationResponse(BaseModel):
    """Response schema for agent validation."""
    
    valid: bool
    errors: List[str]
    warnings: List[str]


class AgentCloneRequest(BaseModel):
    """Request schema for cloning an agent."""
    
    name: str = Field(..., min_length=3, max_length=100, pattern="^[a-z0-9_-]+$")
    display_name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    team_id: Optional[UUID] = None
    
    @field_validator("display_name", "description")
    @classmethod
    def sanitize_html(cls, v: str | None) -> str | None:
        """Sanitize HTML to prevent XSS."""
        if v is None:
            return v
        return html.escape(v)


class AgentExportResponse(BaseModel):
    """Response schema for agent export."""
    
    agent: AgentDetailResponse
    graph_definition: Dict[str, Any]
    memories: List[AgentMemoryResponse]
    version: str = "1.0.0"
    exported_at: datetime


class AgentImportRequest(BaseModel):
    """Request schema for agent import."""
    
    agent_data: Dict[str, Any]
    name: str = Field(..., min_length=3, max_length=100, pattern="^[a-z0-9_-]+$")
    team_id: Optional[UUID] = None
    import_memories: bool = Field(False)