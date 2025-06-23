"""
LLM Provider and API Key models with encryption.
"""
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, JSON, Float, Numeric
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from ..base import BaseModel, TenantAwareModel


class LLMProvider(TenantAwareModel):
    """
    LLM Provider configuration per tenant.
    Supports OpenAI, Anthropic, Google, Azure, Ollama.
    """
    __tablename__ = 'llm_providers'
    
    # Provider Info
    provider_type = Column(String(50), nullable=False)  # openai, anthropic, google, azure, ollama
    display_name = Column(String(255), nullable=False)
    is_default = Column(Boolean, default=False)
    
    # Configuration
    base_url = Column(Text, nullable=True)  # For Azure/Ollama custom endpoints
    api_version = Column(String(50), nullable=True)
    region = Column(String(50), nullable=True)  # For Azure
    
    # Models
    available_models = Column(JSON, default=list)  # List of model IDs
    default_model = Column(String(100), nullable=True)
    
    # Limits
    rate_limit_rpm = Column(Integer, nullable=True)  # Requests per minute
    rate_limit_tpd = Column(Integer, nullable=True)  # Tokens per day
    
    # Status
    is_active = Column(Boolean, default=True)
    last_health_check = Column(DateTime, nullable=True)
    health_status = Column(String(50), default='unknown')  # healthy, degraded, down
    
    # Additional data
    extra_data = Column('metadata', JSON, default=dict)
    
    # Audit
    created_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    
    # Relationships
    api_keys = relationship("LLMAPIKey", back_populates="provider", cascade="all, delete-orphan")
    conversations = relationship("Conversation", back_populates="llm_provider")
    creator = relationship("User", foreign_keys=[created_by])
    
    
    def __repr__(self):
        return f"<LLMProvider(type='{self.provider_type}', name='{self.display_name}')>"


class LLMAPIKey(BaseModel):
    """
    Encrypted API keys for LLM providers.
    Uses AES-256 encryption for secure storage.
    """
    __tablename__ = 'llm_api_keys'
    
    # Foreign Key
    provider_id = Column(UUID(as_uuid=True), ForeignKey('llm_providers.id', ondelete='CASCADE'), nullable=False)
    
    # Encrypted Storage
    key_name = Column(String(255), nullable=False)
    encrypted_key = Column(Text, nullable=False)  # AES-256 encrypted
    key_hint = Column(String(20), nullable=True)  # Last 4 characters for identification
    encryption_key_id = Column(String(100), nullable=True)  # Reference to KMS key
    
    # Usage Tracking
    total_requests = Column(Integer, default=0)
    total_tokens = Column(Integer, default=0)
    total_cost = Column(Numeric(10, 4), default=0.0)
    
    # Status
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    
    # Additional data
    extra_data = Column('metadata', JSON, default=dict)
    
    # Audit
    created_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    rotated_at = Column(DateTime, nullable=True)
    
    # Relationships
    provider = relationship("LLMProvider", back_populates="api_keys")
    creator = relationship("User", foreign_keys=[created_by])
    
    
    def __repr__(self):
        return f"<LLMAPIKey(name='{self.key_name}', hint='***{self.key_hint}')>"