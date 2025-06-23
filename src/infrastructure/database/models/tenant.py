"""
Tenant management models.
"""
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, JSON, Index, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from ..base import BaseModel


class Tenant(BaseModel):
    """
    Tenant model representing an organization/company.
    Root of all multi-tenancy.
    """
    __tablename__ = 'tenants'
    
    # Identity
    name = Column(String(255), nullable=False)
    slug = Column(String(255), unique=True, nullable=False)
    domain = Column(String(255), nullable=True)
    
    # Organization
    industry = Column(String(100), nullable=True)
    company_size = Column(String(50), nullable=True)
    country = Column(String(2), nullable=True)  # ISO country code
    
    # Subscription
    plan_type = Column(String(50), default='trial')  # trial, starter, professional, enterprise
    trial_ends_at = Column(DateTime, nullable=True)
    subscription_ends_at = Column(DateTime, nullable=True)
    
    # Limits (based on plan)
    max_users = Column(Integer, default=5)
    max_teams = Column(Integer, default=1)
    max_agents = Column(Integer, default=3)
    max_monthly_tokens = Column(Integer, default=1000000)
    max_storage_gb = Column(Integer, default=10)
    
    # Configuration
    settings = Column(JSON, default=dict)
    features = Column(JSON, default=list)  # Enabled features
    
    # Status
    is_active = Column(Boolean, default=True)
    activation_date = Column(DateTime, nullable=True)
    
    # Additional data
    extra_data = Column('metadata', JSON, default=dict)
    
    # Relationships
    users = relationship("TenantUser", back_populates="tenant", cascade="all, delete-orphan")
    llm_providers = relationship("LLMProvider", back_populates="tenant", cascade="all, delete-orphan")
    conversations = relationship("Conversation", back_populates="tenant", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Tenant(name='{self.name}', slug='{self.slug}')>"


class TenantUser(BaseModel):
    """
    Association between tenants and users.
    Handles multi-tenancy user membership.
    """
    __tablename__ = 'tenant_users'
    
    # Foreign Keys
    tenant_id = Column(UUID(as_uuid=True), ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    
    # Role & Permissions
    role = Column(String(50), nullable=False, default='member')  # owner, admin, member, viewer
    permissions = Column(JSON, default=list)  # Additional permissions
    
    # Status
    is_active = Column(Boolean, default=True)
    joined_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    
    # Invitation
    invited_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    invitation_accepted_at = Column(DateTime, nullable=True)
    
    # Relationships
    tenant = relationship("Tenant", back_populates="users")
    user = relationship("User", back_populates="tenants", foreign_keys=[user_id])
    inviter = relationship("User", foreign_keys=[invited_by])
    
    # Constraints
    __table_args__ = (
        Index('idx_tenant_users_tenant_id', 'tenant_id'),
        Index('idx_tenant_users_user_id', 'user_id'),
        UniqueConstraint('tenant_id', 'user_id', name='idx_tenant_users_unique'),
    )
    
    def __repr__(self):
        return f"<TenantUser(tenant_id={self.tenant_id}, user_id={self.user_id}, role='{self.role}')>"