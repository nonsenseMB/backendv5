"""
Team collaboration models.
"""
from datetime import datetime

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from ..base import BaseModel, TenantAwareModel


class Team(TenantAwareModel):
    """
    Team model for collaborative workspaces.
    """
    __tablename__ = 'teams'

    # Identity
    name = Column(String(255), nullable=False)
    slug = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    avatar_url = Column(Text, nullable=True)

    # Team Agent
    team_agent_id = Column(UUID(as_uuid=True), ForeignKey('agents.id'), nullable=True)

    # Settings
    settings = Column(JSON, default=lambda: {
        "notifications": True,
        "auto_share_conversations": False,
        "default_share_permission": "read"
    })

    # WebSocket
    ws_channel_id = Column(String(255), unique=True, nullable=True)

    # Status
    is_active = Column(Boolean, default=True)

    # Metrics
    member_count = Column(Integer, default=0)
    active_conversations = Column(Integer, default=0)

    # Additional data
    extra_data = Column('metadata', JSON, default=dict)

    # Audit
    created_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)

    # Relationships
    members = relationship("TeamMember", back_populates="team", cascade="all, delete-orphan")
    creator = relationship("User", foreign_keys=[created_by])
    agents = relationship("Agent", back_populates="team")


    def __repr__(self):
        return f"<Team(name='{self.name}', slug='{self.slug}')>"


class TeamMember(BaseModel):
    """
    Team membership model.
    """
    __tablename__ = 'team_members'

    # Foreign Keys
    team_id = Column(UUID(as_uuid=True), ForeignKey('teams.id', ondelete='CASCADE'), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)

    # Role & Permissions
    role = Column(String(50), nullable=False, default='member')  # owner, admin, member, viewer
    permissions = Column(JSON, default=list)

    # Status
    is_active = Column(Boolean, default=True)
    joined_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Invitation
    invited_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)

    # Relationships
    team = relationship("Team", back_populates="members")
    user = relationship("User", foreign_keys=[user_id])
    inviter = relationship("User", foreign_keys=[invited_by])


    def __repr__(self):
        return f"<TeamMember(team_id={self.team_id}, user_id={self.user_id}, role='{self.role}')>"
