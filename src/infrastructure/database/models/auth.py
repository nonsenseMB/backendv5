"""
Authentication models - NO PASSWORD FIELDS!
All authentication is handled by Authentik.
"""
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from ..base import BaseModel


class User(BaseModel):
    """
    User model - NO PASSWORD FIELD!
    Authentication is handled entirely by Authentik.
    """
    __tablename__ = 'users'
    
    # Authentik Integration
    external_id = Column(String(255), unique=True, nullable=False)  # Authentik user ID
    email = Column(String(255), unique=True, nullable=False)
    username = Column(String(255), unique=True, nullable=True)
    
    # Profile
    full_name = Column(String(255), nullable=True)
    avatar_url = Column(Text, nullable=True)
    language = Column(String(10), default='en')
    timezone = Column(String(50), default='UTC')
    
    # Status
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    last_seen_at = Column(DateTime, nullable=True)
    
    # Additional data
    extra_data = Column('metadata', JSON, default=dict)
    
    # Relationships
    devices = relationship("UserDevice", back_populates="user", cascade="all, delete-orphan")
    tenants = relationship("TenantUser", back_populates="user", foreign_keys="TenantUser.user_id")
    conversations = relationship("Conversation", back_populates="user")
    preferences = relationship("UserPreferences", back_populates="user", uselist=False)
    
    def __repr__(self):
        return f"<User(email='{self.email}', external_id='{self.external_id}')>"


class UserDevice(BaseModel):
    """
    Device-based authentication only.
    Supports WebAuthn, Passkeys, and Device Certificates.
    """
    __tablename__ = 'user_devices'
    
    # Foreign Key
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    
    # Device Info
    device_name = Column(String(255), nullable=False)
    device_type = Column(String(50), nullable=False)  # webauthn, passkey, certificate
    device_id = Column(String(255), unique=True, nullable=False)
    
    # Authentication
    credential_id = Column(String(255), unique=True, nullable=True)
    public_key = Column(Text, nullable=True)
    attestation_object = Column(JSON, nullable=True)
    
    # Trust
    is_trusted = Column(Boolean, default=False)
    trust_score = Column(Float, default=0.0)
    
    # Usage
    last_used_at = Column(DateTime, nullable=True)
    use_count = Column(Integer, default=0)
    
    # Status
    is_active = Column(Boolean, default=True)
    
    # Additional data
    user_agent = Column(Text, nullable=True)
    extra_data = Column('metadata', JSON, default=dict)
    
    # Relationships
    user = relationship("User", back_populates="devices")
    
    
    def __repr__(self):
        return f"<UserDevice(user_id={self.user_id}, device_name='{self.device_name}', type='{self.device_type}')>"