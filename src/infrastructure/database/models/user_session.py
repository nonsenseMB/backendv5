"""
User session management models.
Tracks active user sessions across devices with privacy-compliant data handling.
"""

from datetime import datetime

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from ..base import BaseModel


class UserSession(BaseModel):
    """
    User session model for tracking active sessions across devices.
    Links to Authentik sessions and provides session lifecycle management.
    """
    __tablename__ = 'user_sessions'

    # User and Tenant Context
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False)

    # Device Information
    device_id = Column(UUID(as_uuid=True), ForeignKey('user_devices.id', ondelete='SET NULL'), nullable=True)

    # External Session Linking
    authentik_session_id = Column(String(255), nullable=True)  # Link to Authentik session

    # Privacy-Compliant Client Information
    ip_address_hash = Column(String(64), nullable=True)  # SHA-256 hash of IP for privacy
    user_agent = Column(Text, nullable=True)
    client_info = Column(JSON, default=dict)  # Browser, OS, etc. (anonymized)

    # Session Lifecycle
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_activity = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)

    # Session Status
    is_active = Column(Boolean, default=True)
    terminated_at = Column(DateTime, nullable=True)
    termination_reason = Column(String(100), nullable=True)  # logout, expired, revoked, etc.

    # Session Metadata
    session_type = Column(String(50), default='web')  # web, mobile, api, etc.
    login_method = Column(String(50), nullable=True)  # password, sso, device_cert, etc.

    # Additional session data
    session_data = Column(JSON, default=dict)  # Custom session attributes

    # Relationships
    user = relationship("User", back_populates="sessions")
    tenant = relationship("Tenant")
    device = relationship("UserDevice")
    activities = relationship("SessionActivity", back_populates="session", cascade="all, delete-orphan")

    # Indexes for efficient querying
    __table_args__ = (
        Index('idx_user_sessions_user_id', 'user_id'),
        Index('idx_user_sessions_tenant_id', 'tenant_id'),
        Index('idx_user_sessions_active', 'is_active', 'expires_at'),
        Index('idx_user_sessions_authentik', 'authentik_session_id'),
        Index('idx_user_sessions_device', 'device_id'),
        Index('idx_user_sessions_last_activity', 'last_activity'),
    )

    def __repr__(self):
        return f"<UserSession(user_id={self.user_id}, tenant_id={self.tenant_id}, active={self.is_active})>"

    def is_expired(self) -> bool:
        """Check if session has expired."""
        return datetime.utcnow() > self.expires_at

    def is_valid(self) -> bool:
        """Check if session is valid (active and not expired)."""
        return self.is_active and not self.is_expired()

    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = datetime.utcnow()

    def terminate(self, reason: str = "logout") -> None:
        """Terminate the session."""
        self.is_active = False
        self.terminated_at = datetime.utcnow()
        self.termination_reason = reason


class SessionActivity(BaseModel):
    """
    Session activity tracking for security monitoring and analytics.
    Records user actions during a session for audit and security purposes.
    """
    __tablename__ = 'session_activities'

    # Session Reference
    session_id = Column(UUID(as_uuid=True), ForeignKey('user_sessions.id', ondelete='CASCADE'), nullable=False)

    # Activity Information
    activity_type = Column(String(100), nullable=False)  # api_call, tenant_switch, login, logout, etc.
    activity_category = Column(String(50), nullable=True)  # auth, data, admin, etc.

    # Timing
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    duration_ms = Column(Integer, nullable=True)  # For activities with measurable duration

    # Request Context
    endpoint = Column(String(255), nullable=True)  # API endpoint called
    http_method = Column(String(10), nullable=True)  # GET, POST, etc.
    status_code = Column(Integer, nullable=True)  # HTTP response status

    # Activity Details
    details = Column(JSON, default=dict)  # Activity-specific data (PII-filtered)
    resource_type = Column(String(100), nullable=True)  # conversation, document, etc.
    resource_id = Column(UUID(as_uuid=True), nullable=True)  # ID of accessed resource

    # Security Context
    ip_address_hash = Column(String(64), nullable=True)  # Same as session for correlation
    user_agent_hash = Column(String(64), nullable=True)  # Hashed for privacy

    # Result and Error Tracking
    success = Column(Boolean, nullable=True)
    error_code = Column(String(50), nullable=True)
    error_message = Column(Text, nullable=True)  # Sanitized error message

    # Relationships
    session = relationship("UserSession", back_populates="activities")

    # Indexes for efficient querying
    __table_args__ = (
        Index('idx_session_activities_session_id', 'session_id'),
        Index('idx_session_activities_timestamp', 'timestamp'),
        Index('idx_session_activities_type', 'activity_type'),
        Index('idx_session_activities_category', 'activity_category'),
        Index('idx_session_activities_resource', 'resource_type', 'resource_id'),
        Index('idx_session_activities_success', 'success'),
    )

    def __repr__(self):
        return f"<SessionActivity(session_id={self.session_id}, type='{self.activity_type}', timestamp={self.timestamp})>"


class SessionSecurityEvent(BaseModel):
    """
    Security events related to sessions for enhanced monitoring.
    Tracks suspicious activities and security-relevant events.
    """
    __tablename__ = 'session_security_events'

    # Session Reference (nullable for events without active session)
    session_id = Column(UUID(as_uuid=True), ForeignKey('user_sessions.id', ondelete='CASCADE'), nullable=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)

    # Event Information
    event_type = Column(String(100), nullable=False)  # suspicious_login, concurrent_sessions, etc.
    severity = Column(String(20), nullable=False, default='medium')  # low, medium, high, critical

    # Timing
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Context
    ip_address_hash = Column(String(64), nullable=True)
    user_agent = Column(Text, nullable=True)
    location_info = Column(JSON, nullable=True)  # Approximate location data

    # Event Details
    description = Column(Text, nullable=False)
    details = Column(JSON, default=dict)

    # Response and Resolution
    action_taken = Column(String(100), nullable=True)  # block, alert, require_mfa, etc.
    resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)

    # Relationships
    session = relationship("UserSession")
    user = relationship("User", foreign_keys=[user_id])
    resolver = relationship("User", foreign_keys=[resolved_by])

    # Indexes
    __table_args__ = (
        Index('idx_security_events_user_id', 'user_id'),
        Index('idx_security_events_session_id', 'session_id'),
        Index('idx_security_events_timestamp', 'timestamp'),
        Index('idx_security_events_severity', 'severity'),
        Index('idx_security_events_type', 'event_type'),
        Index('idx_security_events_resolved', 'resolved'),
    )

    def __repr__(self):
        return f"<SessionSecurityEvent(user_id={self.user_id}, type='{self.event_type}', severity='{self.severity}')>"
