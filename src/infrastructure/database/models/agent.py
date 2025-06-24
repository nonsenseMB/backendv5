"""
Agent system models for LangGraph-based AI assistants.
"""

from sqlalchemy import JSON, ARRAY, Boolean, Column, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from ..base import BaseModel, TenantAwareModel


class Agent(TenantAwareModel):
    """
    Agent model for AI assistants with LangGraph integration.
    """
    __tablename__ = 'agents'

    # Identity
    name = Column(String(255), nullable=False)
    display_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    avatar_url = Column(Text, nullable=True)

    # Type & Purpose
    agent_type = Column(String(50), nullable=False, default='general')  # general, specialist, coordinator, team
    specialization = Column(String(100), nullable=True)  # coding, research, writing, analysis

    # LangGraph Configuration
    graph_definition = Column(JSON, nullable=False)  # LangGraph flow definition
    default_llm_provider_id = Column(UUID(as_uuid=True), ForeignKey('llm_providers.id'), nullable=True)
    model_preferences = Column(JSON, default=dict)

    # Capabilities
    capabilities = Column(JSON, default=list)  # ['web_search', 'code_execution', 'file_access']
    tool_ids = Column(ARRAY(UUID(as_uuid=True)), default=list)  # Available tools
    mcp_connection_ids = Column(ARRAY(UUID(as_uuid=True)), default=list)  # MCP servers

    # Behavior
    system_prompt = Column(Text, nullable=True)
    temperature = Column(Float, default=0.7)
    response_style = Column(String(50), nullable=True)  # concise, detailed, creative

    # Knowledge Access
    knowledge_base_ids = Column(ARRAY(UUID(as_uuid=True)), default=list)
    memory_access_level = Column(String(50), default='conversation')  # none, conversation, user, team

    # Team Assignment
    team_id = Column(UUID(as_uuid=True), ForeignKey('teams.id'), nullable=True)

    # Access Control
    is_public = Column(Boolean, default=False)
    allowed_roles = Column(JSON, default=lambda: ["admin", "member"])

    # Status
    is_active = Column(Boolean, default=True)

    # Metrics
    total_conversations = Column(Integer, default=0)
    satisfaction_score = Column(Float, default=0.0)
    avg_response_time_ms = Column(Integer, default=0)

    # Additional data
    tags = Column(JSON, default=list)
    extra_data = Column('metadata', JSON, default=dict)

    # Audit
    created_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)

    # Relationships
    creator = relationship("User", foreign_keys=[created_by])
    team = relationship("Team", back_populates="agents")
    tools = relationship("AgentTool", back_populates="agent", cascade="all, delete-orphan")
    memories = relationship("AgentMemory", back_populates="agent", cascade="all, delete-orphan")


class AgentTool(BaseModel):
    """
    Many-to-many relationship between agents and tools.
    """
    __tablename__ = 'agent_tools'

    # Foreign Keys
    agent_id = Column(UUID(as_uuid=True), ForeignKey('agents.id', ondelete='CASCADE'), nullable=False)
    tool_id = Column(UUID(as_uuid=True), ForeignKey('tool_definitions.id'), nullable=False)

    # Configuration
    is_enabled = Column(Boolean, default=True)
    custom_parameters = Column(JSON, default=dict)
    rate_limit_override = Column(Integer, nullable=True)

    # Usage
    usage_count = Column(Integer, default=0)
    last_used_at = Column(Text, nullable=True)  # Using Text for timestamp to avoid import issues

    # Relationships
    agent = relationship("Agent", back_populates="tools")
    tool = relationship("ToolDefinition")


class AgentMemory(TenantAwareModel):
    """
    Agent-specific learned memories and patterns.
    """
    __tablename__ = 'agent_memories'

    # Foreign Keys
    agent_id = Column(UUID(as_uuid=True), ForeignKey('agents.id', ondelete='CASCADE'), nullable=False)
    
    # Context
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    team_id = Column(UUID(as_uuid=True), ForeignKey('teams.id'), nullable=True)
    conversation_id = Column(UUID(as_uuid=True), ForeignKey('conversations.id'), nullable=True)

    # Memory Content
    memory_type = Column(String(50), nullable=False)  # learning, pattern, feedback, optimization
    content = Column(Text, nullable=False)

    # Learning Metrics
    confidence = Column(Float, default=0.5)
    usefulness_score = Column(Float, default=0.0)
    application_count = Column(Integer, default=0)

    # Lifecycle
    is_active = Column(Boolean, default=True)
    expires_at = Column(Text, nullable=True)  # Using Text for timestamp

    # Metadata
    source = Column(String(50), nullable=True)  # user_feedback, self_learning, system
    extra_data = Column('metadata', JSON, default=dict)

    # Timestamps
    last_applied_at = Column(Text, nullable=True)  # Using Text for timestamp

    # Relationships
    agent = relationship("Agent", back_populates="memories")


    def __repr__(self):
        return f"<Agent(name='{self.name}', type='{self.agent_type}')>"
