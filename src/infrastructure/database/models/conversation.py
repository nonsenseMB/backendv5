"""
Conversation and messaging models.
"""

from sqlalchemy import JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from ..base import BaseModel, TenantAwareModel


class Conversation(TenantAwareModel):
    """
    Conversation model for chat interactions.
    """
    __tablename__ = 'conversations'

    # Ownership
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    team_id = Column(UUID(as_uuid=True), ForeignKey('teams.id'), nullable=True)

    # Identity
    title = Column(String(500), nullable=True)
    summary = Column(Text, nullable=True)

    # Agent Assignment
    agent_id = Column(UUID(as_uuid=True), ForeignKey('agents.id'), nullable=True)

    # Configuration
    llm_provider_id = Column(UUID(as_uuid=True), ForeignKey('llm_providers.id'), nullable=True)
    model_settings = Column(JSON, default=lambda: {
        "model": None,
        "temperature": 0.7,
        "max_tokens": 4096,
        "top_p": 1.0
    })

    # Memory Management
    message_count = Column(Integer, default=0)
    checkpoint_frequency = Column(Integer, default=50)  # Create checkpoint every N messages
    last_checkpoint_at = Column(DateTime, nullable=True)

    # WebSocket
    ws_channel_id = Column(String(255), nullable=True)  # For real-time updates

    # Status
    is_active = Column(Boolean, default=True)
    is_archived = Column(Boolean, default=False)

    # Additional data
    tags = Column(JSON, default=list)
    extra_data = Column('metadata', JSON, default=dict)

    # Timestamps
    last_message_at = Column(DateTime, nullable=True)

    # Relationships
    user = relationship("User", back_populates="conversations")
    llm_provider = relationship("LLMProvider", back_populates="conversations")
    messages = relationship("Message", back_populates="conversation", cascade="all, delete-orphan")
    checkpoints = relationship("ConversationCheckpoint", back_populates="conversation", cascade="all, delete-orphan")
    # Note: Memory relationships removed - memory is stored in vector DB (Milvus/Chroma)


    def __repr__(self):
        return f"<Conversation(id={self.id}, title='{self.title}')>"


class Message(BaseModel):
    """
    Individual messages within conversations.
    """
    __tablename__ = 'messages'

    # Foreign Key
    conversation_id = Column(UUID(as_uuid=True), ForeignKey('conversations.id', ondelete='CASCADE'), nullable=False)

    # Sequencing
    sequence_number = Column(Integer, nullable=False)

    # Content
    role = Column(String(50), nullable=False)  # user, assistant, system, tool
    content = Column(Text, nullable=False)

    # LLM Details
    model_used = Column(String(100), nullable=True)
    provider_id = Column(UUID(as_uuid=True), ForeignKey('llm_providers.id'), nullable=True)

    # Token Usage
    prompt_tokens = Column(Integer, nullable=True)
    completion_tokens = Column(Integer, nullable=True)
    total_tokens = Column(Integer, nullable=True)

    # Tool Usage
    tool_calls = Column(JSON, nullable=True)  # Array of tool calls
    tool_results = Column(JSON, nullable=True)  # Tool execution results

    # Threading
    parent_message_id = Column(UUID(as_uuid=True), ForeignKey('messages.id'), nullable=True)

    # WebSocket
    ws_delivered = Column(Boolean, default=False)
    ws_delivered_at = Column(DateTime, nullable=True)

    # Status
    is_visible = Column(Boolean, default=True)
    is_edited = Column(Boolean, default=False)
    error = Column(JSON, nullable=True)

    # Additional data
    extra_data = Column('metadata', JSON, default=dict)

    # Timestamps
    edited_at = Column(DateTime, nullable=True)

    # Relationships
    conversation = relationship("Conversation", back_populates="messages")
    parent_message = relationship("Message", remote_side="Message.id")


    def __repr__(self):
        return f"<Message(role='{self.role}', conversation_id={self.conversation_id})>"


class ConversationCheckpoint(BaseModel):
    """
    Checkpoints for conversation summarization.
    Reduces token usage by summarizing older messages.
    """
    __tablename__ = 'conversation_checkpoints'

    # Foreign Key
    conversation_id = Column(UUID(as_uuid=True), ForeignKey('conversations.id', ondelete='CASCADE'), nullable=False)

    # Checkpoint Info
    checkpoint_number = Column(Integer, nullable=False)
    message_count = Column(Integer, nullable=False)

    # Summary
    summary = Column(Text, nullable=False)
    key_points = Column(JSON, default=list)
    entities_mentioned = Column(JSON, default=list)

    # Token Savings
    original_tokens = Column(Integer, nullable=True)
    summary_tokens = Column(Integer, nullable=True)
    compression_ratio = Column(Float, nullable=True)

    # Additional data
    extra_data = Column('metadata', JSON, default=dict)

    # Relationships
    conversation = relationship("Conversation", back_populates="checkpoints")


    def __repr__(self):
        return f"<ConversationCheckpoint(conversation_id={self.conversation_id}, number={self.checkpoint_number})>"
