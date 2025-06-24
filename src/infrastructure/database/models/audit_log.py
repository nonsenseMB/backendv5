"""
Audit logging database models for comprehensive security and compliance tracking.
Implements persistent audit trail with GDPR-compliant design.
"""

from datetime import datetime

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from ..base import BaseModel


class AuditLog(BaseModel):
    """
    Comprehensive audit log entry for security monitoring and compliance.
    Stores all authentication, authorization, and system events with full context.
    """
    __tablename__ = 'audit_logs'

    # Event Information
    event_type = Column(String(100), nullable=False)  # auth.login.success, tenant.switched, etc.
    event_category = Column(String(50), nullable=False)  # auth, data, admin, security, system
    severity = Column(String(20), nullable=False, default='info')  # info, warning, critical

    # Timing
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)

    # User Context
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey('tenants.id', ondelete='SET NULL'), nullable=True)
    session_id = Column(UUID(as_uuid=True), ForeignKey('user_sessions.id', ondelete='SET NULL'), nullable=True)

    # Request Context (Privacy-Compliant)
    ip_address_hash = Column(String(64), nullable=True)  # SHA-256 hash for privacy
    user_agent = Column(Text, nullable=True)
    request_id = Column(String(255), nullable=True)

    # Resource Context
    resource_type = Column(String(100), nullable=True)  # conversation, document, user, etc.
    resource_id = Column(UUID(as_uuid=True), nullable=True)
    action = Column(String(100), nullable=True)  # create, read, update, delete, grant, revoke

    # Event Details
    details = Column(JSON, default=dict)  # Additional event-specific data (PII-filtered)

    # Result and Status
    success = Column(Boolean, nullable=True)  # Whether the action succeeded
    error_code = Column(String(50), nullable=True)  # Error code if action failed
    error_message = Column(Text, nullable=True)  # Sanitized error message

    # Compliance and Retention
    retention_date = Column(DateTime, nullable=True)  # When this log can be deleted
    is_sensitive = Column(Boolean, default=False)  # Marks sensitive events for special handling
    compliance_tags = Column(JSON, default=list)  # GDPR, SOX, HIPAA, etc.

    # Performance Metrics
    duration_ms = Column(Integer, nullable=True)  # Action duration in milliseconds
    response_size_bytes = Column(Integer, nullable=True)  # Response size

    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    tenant = relationship("Tenant", foreign_keys=[tenant_id])
    session = relationship("UserSession", foreign_keys=[session_id])

    # Comprehensive indexing for efficient querying
    __table_args__ = (
        # Primary query patterns
        Index('idx_audit_user_timestamp', 'user_id', 'timestamp'),
        Index('idx_audit_tenant_timestamp', 'tenant_id', 'timestamp'),
        Index('idx_audit_event_timestamp', 'event_type', 'timestamp'),
        Index('idx_audit_session', 'session_id'),

        # Security and compliance queries
        Index('idx_audit_severity_timestamp', 'severity', 'timestamp'),
        Index('idx_audit_category_timestamp', 'event_category', 'timestamp'),
        Index('idx_audit_success', 'success', 'timestamp'),
        Index('idx_audit_sensitive', 'is_sensitive', 'timestamp'),

        # Resource-based queries
        Index('idx_audit_resource', 'resource_type', 'resource_id', 'timestamp'),
        Index('idx_audit_action', 'action', 'timestamp'),

        # Retention and cleanup
        Index('idx_audit_retention', 'retention_date'),
        Index('idx_audit_compliance_tags', 'compliance_tags'),

        # Performance queries
        Index('idx_audit_ip_hash', 'ip_address_hash', 'timestamp'),
        Index('idx_audit_request_id', 'request_id'),
    )

    def __repr__(self):
        return f"<AuditLog(event_type='{self.event_type}', user_id={self.user_id}, timestamp={self.timestamp})>"

    def is_expired(self) -> bool:
        """Check if this audit log has passed its retention date."""
        if not self.retention_date:
            return False
        return datetime.utcnow() > self.retention_date

    def get_sanitized_details(self) -> dict:
        """Get event details with additional PII filtering applied."""
        if not self.details:
            return {}

        # Additional sanitization for audit logs
        sanitized = self.details.copy()

        # Remove any potentially sensitive fields that might have been missed
        sensitive_keys = [
            'password', 'token', 'secret', 'key', 'auth', 'credential',
            'ssn', 'social_security', 'credit_card', 'card_number',
            'phone', 'email_raw', 'ip_address'  # Use hashed versions instead
        ]

        for key in list(sanitized.keys()):
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = '[REDACTED]'

        return sanitized


class AuditLogQuery(BaseModel):
    """
    Audit log query tracking for compliance and monitoring.
    Records who accessed audit logs and when.
    """
    __tablename__ = 'audit_log_queries'

    # Query Information
    query_type = Column(String(50), nullable=False)  # user_logs, security_review, compliance_export
    query_description = Column(Text, nullable=True)

    # Query Parameters
    start_date = Column(DateTime, nullable=True)
    end_date = Column(DateTime, nullable=True)
    user_filter = Column(UUID(as_uuid=True), nullable=True)
    tenant_filter = Column(UUID(as_uuid=True), nullable=True)
    event_types = Column(JSON, default=list)

    # Query Context
    requested_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    requested_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    ip_address_hash = Column(String(64), nullable=True)
    justification = Column(Text, nullable=True)  # Required for sensitive queries

    # Results
    records_returned = Column(Integer, nullable=True)
    query_duration_ms = Column(Integer, nullable=True)

    # Approval Workflow (for sensitive data access)
    requires_approval = Column(Boolean, default=False)
    approved_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    approval_reason = Column(Text, nullable=True)

    # Relationships
    requester = relationship("User", foreign_keys=[requested_by])
    approver = relationship("User", foreign_keys=[approved_by])

    # Indexing
    __table_args__ = (
        Index('idx_audit_query_requester', 'requested_by', 'requested_at'),
        Index('idx_audit_query_approval', 'requires_approval', 'approved_at'),
        Index('idx_audit_query_type', 'query_type', 'requested_at'),
    )

    def __repr__(self):
        return f"<AuditLogQuery(type='{self.query_type}', requested_by={self.requested_by}, at={self.requested_at})>"


class AuditLogRetentionPolicy(BaseModel):
    """
    Audit log retention policies for different event types and compliance requirements.
    Defines how long different types of audit logs should be retained.
    """
    __tablename__ = 'audit_log_retention_policies'

    # Policy Identification
    policy_name = Column(String(100), nullable=False, unique=True)
    description = Column(Text, nullable=True)

    # Matching Criteria
    event_types = Column(JSON, default=list)  # Which event types this policy applies to
    event_categories = Column(JSON, default=list)  # Which categories this policy applies to
    severity_levels = Column(JSON, default=list)  # Which severity levels
    compliance_tags = Column(JSON, default=list)  # Which compliance frameworks

    # Retention Rules
    retention_days = Column(Integer, nullable=False)  # How long to retain logs
    is_default = Column(Boolean, default=False)  # Whether this is the default policy

    # Special Handling
    archive_after_days = Column(Integer, nullable=True)  # Move to cold storage after N days
    encrypt_sensitive = Column(Boolean, default=True)  # Encrypt sensitive logs
    require_approval_for_access = Column(Boolean, default=False)  # Require approval to access

    # Policy Status
    is_active = Column(Boolean, default=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    last_modified_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    last_modified_at = Column(DateTime, nullable=True)

    # Relationships
    creator = relationship("User", foreign_keys=[created_by])
    modifier = relationship("User", foreign_keys=[last_modified_by])

    # Indexing
    __table_args__ = (
        Index('idx_retention_policy_active', 'is_active'),
        Index('idx_retention_policy_default', 'is_default'),
        Index('idx_retention_policy_modified', 'last_modified_at'),
    )

    def __repr__(self):
        return f"<AuditLogRetentionPolicy(name='{self.policy_name}', retention_days={self.retention_days})>"

    def applies_to_event(self, event_type: str, event_category: str, severity: str, compliance_tags: list) -> bool:
        """Check if this retention policy applies to a given audit event."""
        # Check event types
        if self.event_types and event_type not in self.event_types:
            return False

        # Check event categories
        if self.event_categories and event_category not in self.event_categories:
            return False

        # Check severity levels
        if self.severity_levels and severity not in self.severity_levels:
            return False

        # Check compliance tags (any overlap)
        if self.compliance_tags and not any(tag in compliance_tags for tag in self.compliance_tags):
            return False

        return True
