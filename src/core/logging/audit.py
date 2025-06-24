"""Audit logging for DSGVO compliance and security monitoring."""
from datetime import datetime
from enum import Enum
from typing import Any

import structlog


class AuditEventType(Enum):
    """Types of audit events for compliance tracking."""
    # Authentication & Authorization
    USER_LOGIN = "USER_LOGIN"
    USER_LOGOUT = "USER_LOGOUT"
    LOGIN_FAILED = "LOGIN_FAILED"
    PASSWORD_CHANGE = "PASSWORD_CHANGE"
    PERMISSION_CHANGE = "PERMISSION_CHANGE"
    AUTH_TOKEN_EXCHANGED = "AUTH_TOKEN_EXCHANGED"
    AUTH_TOKEN_EXCHANGE_FAILED = "AUTH_TOKEN_EXCHANGE_FAILED"
    AUTH_TOKEN_REFRESHED = "AUTH_TOKEN_REFRESHED"
    AUTH_TOKEN_REFRESH_FAILED = "AUTH_TOKEN_REFRESH_FAILED"
    AUTH_LOGIN_SUCCESS = "AUTH_LOGIN_SUCCESS"
    AUTH_ACCESS_DENIED = "AUTH_ACCESS_DENIED"
    
    # Device Authentication
    DEVICE_REGISTERED = "DEVICE_REGISTERED"
    DEVICE_REMOVED = "DEVICE_REMOVED"
    DEVICE_UPDATED = "DEVICE_UPDATED"
    DEVICE_AUTH_SUCCESS = "DEVICE_AUTH_SUCCESS"
    DEVICE_AUTH_FAILED = "DEVICE_AUTH_FAILED"

    # Data Access & Modification
    DATA_ACCESS = "DATA_ACCESS"
    DATA_CREATE = "DATA_CREATE"
    DATA_UPDATE = "DATA_UPDATE"
    DATA_DELETE = "DATA_DELETE"
    DATA_EXPORT = "DATA_EXPORT"

    # System Events
    CONFIG_CHANGE = "CONFIG_CHANGE"
    SYSTEM_START = "SYSTEM_START"
    SYSTEM_STOP = "SYSTEM_STOP"
    ERROR_OCCURRED = "ERROR_OCCURRED"
    SECURITY_CHECK = "SECURITY_CHECK"
    SECURITY_ALERT = "SECURITY_ALERT"

    # DSGVO Events
    CONSENT_GIVEN = "CONSENT_GIVEN"
    CONSENT_WITHDRAWN = "CONSENT_WITHDRAWN"
    DATA_ERASURE_REQUEST = "DATA_ERASURE_REQUEST"
    DATA_PORTABILITY_REQUEST = "DATA_PORTABILITY_REQUEST"


class AuditSeverity(Enum):
    """Severity levels for audit events."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def log_audit_event(
    event_type: AuditEventType,
    user_id: str | None = None,
    tenant_id: str | None = None,
    details: dict[str, Any] | None = None,
    severity: AuditSeverity = AuditSeverity.MEDIUM,
    resource: str | None = None,
    action: str | None = None
) -> None:
    """
    Log an audit event for compliance and security monitoring.

    Args:
        event_type: Type of audit event
        user_id: ID of the user performing the action
        tenant_id: ID of the tenant context
        details: Additional event details (will be PII-filtered)
        severity: Severity level of the event
        resource: Resource being accessed/modified
        action: Specific action being performed
    """
    logger = structlog.get_logger("audit")

    audit_data = {
        "audit_event": True,
        "event_type": event_type.value,
        "severity": severity.value,
        "timestamp": datetime.utcnow().isoformat(),
        "user_id": user_id,
        "tenant_id": tenant_id,
        "resource": resource,
        "action": action,
        **(details or {})
    }

    # Log with appropriate level based on severity
    if severity == AuditSeverity.CRITICAL:
        logger.error("Audit event", **audit_data)
    elif severity == AuditSeverity.HIGH:
        logger.warning("Audit event", **audit_data)
    else:
        logger.info("Audit event", **audit_data)


def log_user_action(
    action: str,
    user_id: str,
    resource: str | None = None,
    details: dict[str, Any] | None = None,
    severity: AuditSeverity = AuditSeverity.MEDIUM
) -> None:
    """Convenience function for logging user actions."""
    log_audit_event(
        event_type=AuditEventType.DATA_ACCESS,
        user_id=user_id,
        action=action,
        resource=resource,
        details=details,
        severity=severity
    )


def log_login_attempt(
    user_id: str,
    success: bool,
    ip_address: str | None = None,
    user_agent: str | None = None
) -> None:
    """Log authentication attempts."""
    event_type = AuditEventType.USER_LOGIN if success else AuditEventType.LOGIN_FAILED
    severity = AuditSeverity.MEDIUM if success else AuditSeverity.HIGH

    log_audit_event(
        event_type=event_type,
        user_id=user_id,
        severity=severity,
        details={
            "ip_address": ip_address,
            "user_agent": user_agent,
            "success": success
        }
    )


def log_data_access(
    user_id: str,
    table_name: str,
    operation: str,
    record_id: str | None = None,
    affected_fields: list[str] | None = None
) -> None:
    """Log database access for DSGVO compliance."""
    log_audit_event(
        event_type=AuditEventType.DATA_ACCESS,
        user_id=user_id,
        resource=table_name,
        action=operation,
        details={
            "record_id": record_id,
            "affected_fields": affected_fields
        }
    )


def log_dsgvo_event(
    event_type: AuditEventType,
    user_id: str,
    data_subject_id: str | None = None,
    details: dict[str, Any] | None = None
) -> None:
    """Log DSGVO-specific events."""
    log_audit_event(
        event_type=event_type,
        user_id=user_id,
        severity=AuditSeverity.HIGH,
        details={
            "data_subject_id": data_subject_id,
            **(details or {})
        }
    )
