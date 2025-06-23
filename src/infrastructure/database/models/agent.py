"""
Agent system models (minimal for Phase 1).
Full implementation will come in Phase 2.
"""

from sqlalchemy import JSON, Boolean, Column, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from ..base import TenantAwareModel


class Agent(TenantAwareModel):
    """
    Agent model for AI assistants.
    Placeholder for Phase 2 implementation.
    """
    __tablename__ = 'agents'

    # Identity
    name = Column(String(255), nullable=False)
    display_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    avatar_url = Column(Text, nullable=True)

    # Type & Purpose
    agent_type = Column(String(50), nullable=False, default='general')  # general, specialist, coordinator, team
    specialization = Column(String(100), nullable=True)

    # LangGraph Configuration (Phase 2)
    graph_definition = Column(JSON, nullable=True)  # LangGraph flow definition
    default_llm_provider_id = Column(UUID(as_uuid=True), ForeignKey('llm_providers.id'), nullable=True)
    model_preferences = Column(JSON, default=dict)

    # Status
    is_active = Column(Boolean, default=True)

    # Additional data
    extra_data = Column('metadata', JSON, default=dict)

    # Audit
    created_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)

    # Relationships
    creator = relationship("User", foreign_keys=[created_by])


    def __repr__(self):
        return f"<Agent(name='{self.name}', type='{self.agent_type}')>"
