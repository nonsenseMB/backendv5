"""
Comprehensive authentication and authorization audit logging service.
Provides database-backed audit trail with GDPR compliance and retention management.
"""

import hashlib
from datetime import datetime, timedelta
from enum import Enum
from typing import Any
from uuid import UUID

from sqlalchemy import desc
from sqlalchemy.orm import Session

from ...infrastructure.database.models.audit_log import AuditLog, AuditLogQuery, AuditLogRetentionPolicy
from ..logging import get_logger

logger = get_logger(__name__)


class AuthAuditEvent(str, Enum):
    """Enhanced authentication and authorization audit events."""
    # Authentication Events
    LOGIN_SUCCESS = "auth.login.success"
    LOGIN_FAILED = "auth.login.failed"
    LOGOUT = "auth.logout"
    TOKEN_ISSUED = "auth.token.issued"
    TOKEN_REFRESHED = "auth.token.refreshed"
    TOKEN_REVOKED = "auth.token.revoked"
    TOKEN_EXPIRED = "auth.token.expired"

    # Device Authentication
    DEVICE_REGISTERED = "auth.device.registered"
    DEVICE_REMOVED = "auth.device.removed"
    DEVICE_UPDATED = "auth.device.updated"
    DEVICE_AUTH_SUCCESS = "auth.device.success"
    DEVICE_AUTH_FAILED = "auth.device.failed"
    DEVICE_TRUST_GRANTED = "auth.device.trust_granted"
    DEVICE_TRUST_REVOKED = "auth.device.trust_revoked"

    # Authorization Events
    PERMISSION_GRANTED = "auth.permission.granted"
    PERMISSION_DENIED = "auth.permission.denied"
    ROLE_ASSIGNED = "auth.role.assigned"
    ROLE_REMOVED = "auth.role.removed"
    ROLE_CREATED = "auth.role.created"
    ROLE_UPDATED = "auth.role.updated"
    ROLE_DELETED = "auth.role.deleted"

    # Tenant Management
    TENANT_SWITCHED = "auth.tenant.switched"
    TENANT_ACCESS_GRANTED = "auth.tenant.access_granted"
    TENANT_ACCESS_DENIED = "auth.tenant.access_denied"
    TENANT_MEMBERSHIP_ADDED = "auth.tenant.membership_added"
    TENANT_MEMBERSHIP_REMOVED = "auth.tenant.membership_removed"

    # Session Management
    SESSION_CREATED = "auth.session.created"
    SESSION_TERMINATED = "auth.session.terminated"
    SESSION_EXPIRED = "auth.session.expired"
    SESSION_HIJACK_DETECTED = "auth.session.hijack_detected"
    CONCURRENT_SESSION_LIMIT = "auth.session.concurrent_limit"

    # Profile and User Management
    PROFILE_UPDATED = "user.profile.updated"
    PROFILE_VIEWED = "user.profile.viewed"
    PASSWORD_CHANGED = "user.password.changed"
    EMAIL_CHANGED = "user.email.changed"
    ACCOUNT_LOCKED = "user.account.locked"
    ACCOUNT_UNLOCKED = "user.account.unlocked"
    ACCOUNT_DELETION_REQUESTED = "user.deletion.requested"
    ACCOUNT_DELETED = "user.deleted"

    # Security Events
    SUSPICIOUS_LOGIN = "security.suspicious_login"
    MULTIPLE_FAILED_LOGINS = "security.multiple_failed_logins"
    UNUSUAL_LOCATION = "security.unusual_location"
    PRIVILEGE_ESCALATION = "security.privilege_escalation"
    DATA_EXPORT = "security.data_export"
    ADMIN_ACTION = "security.admin_action"

    # System Events
    SYSTEM_START = "system.start"
    SYSTEM_STOP = "system.stop"
    CONFIG_CHANGE = "system.config.changed"
    BACKUP_CREATED = "system.backup.created"
    BACKUP_RESTORED = "system.backup.restored"


class AuditSeverity(str, Enum):
    """Audit event severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AuditCategory(str, Enum):
    """Audit event categories for organization and filtering."""
    AUTH = "auth"
    DATA = "data"
    ADMIN = "admin"
    SECURITY = "security"
    SYSTEM = "system"
    USER = "user"
    TENANT = "tenant"


class AuthAuditService:
    """
    Comprehensive audit logging service with database persistence.
    Handles audit event creation, querying, and retention management.
    """

    def __init__(self, db: Session):
        self.db = db
        self._default_retention_days = 2555  # 7 years for security logs

    async def log_auth_event(
        self,
        event_type: AuthAuditEvent,
        user_id: UUID | None = None,
        tenant_id: UUID | None = None,
        session_id: UUID | None = None,
        resource_type: str | None = None,
        resource_id: UUID | None = None,
        action: str | None = None,
        details: dict[str, Any] | None = None,
        severity: AuditSeverity = AuditSeverity.INFO,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
        success: bool | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
        duration_ms: int | None = None,
        response_size_bytes: int | None = None,
        compliance_tags: list[str] | None = None
    ) -> AuditLog:
        """
        Log a comprehensive audit event to the database.
        
        Args:
            event_type: Type of audit event
            user_id: ID of the user performing the action
            tenant_id: ID of the tenant context
            session_id: ID of the user session
            resource_type: Type of resource being accessed
            resource_id: ID of the specific resource
            action: Action being performed (create, read, update, delete, etc.)
            details: Additional event-specific details (will be PII-filtered)
            severity: Severity level of the event
            ip_address: Client IP address (will be hashed for privacy)
            user_agent: Client user agent string
            request_id: Request ID for correlation
            success: Whether the action succeeded
            error_code: Error code if action failed
            error_message: Sanitized error message
            duration_ms: Action duration in milliseconds
            response_size_bytes: Response size in bytes
            compliance_tags: Compliance framework tags (GDPR, SOX, etc.)
            
        Returns:
            Created AuditLog entry
        """
        try:
            # Determine event category
            event_category = self._get_event_category(event_type)

            # Hash IP address for privacy
            ip_hash = None
            if ip_address:
                ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()

            # Filter and sanitize details
            sanitized_details = self._sanitize_details(details or {})

            # Calculate retention date based on policies
            retention_date = await self._calculate_retention_date(
                event_type, event_category, severity, compliance_tags or []
            )

            # Determine if this is a sensitive event
            is_sensitive = self._is_sensitive_event(event_type, severity)

            # Create audit log entry
            audit_log = AuditLog(
                event_type=event_type.value,
                event_category=event_category.value,
                severity=severity.value,
                user_id=user_id,
                tenant_id=tenant_id,
                session_id=session_id,
                ip_address_hash=ip_hash,
                user_agent=user_agent,
                request_id=request_id,
                resource_type=resource_type,
                resource_id=resource_id,
                action=action,
                details=sanitized_details,
                success=success,
                error_code=error_code,
                error_message=error_message,
                duration_ms=duration_ms,
                response_size_bytes=response_size_bytes,
                retention_date=retention_date,
                is_sensitive=is_sensitive,
                compliance_tags=compliance_tags or []
            )

            self.db.add(audit_log)
            self.db.commit()
            self.db.refresh(audit_log)

            # Also log to structured logs for real-time monitoring
            logger.info(
                "Audit event logged",
                audit_id=str(audit_log.id),
                event_type=event_type.value,
                user_id=str(user_id) if user_id else None,
                tenant_id=str(tenant_id) if tenant_id else None,
                severity=severity.value,
                success=success
            )

            return audit_log

        except Exception as e:
            self.db.rollback()
            logger.error(
                "Failed to log audit event",
                event_type=event_type.value,
                user_id=str(user_id) if user_id else None,
                error=str(e)
            )
            raise

    async def query_audit_logs(
        self,
        requester_id: UUID,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        user_filter: UUID | None = None,
        tenant_filter: UUID | None = None,
        event_types: list[str] | None = None,
        event_categories: list[str] | None = None,
        severity_levels: list[str] | None = None,
        success_filter: bool | None = None,
        resource_type: str | None = None,
        limit: int = 100,
        offset: int = 0,
        justification: str | None = None,
        ip_address: str | None = None
    ) -> dict[str, Any]:
        """
        Query audit logs with comprehensive filtering and access control.
        
        Args:
            requester_id: ID of user requesting the logs
            start_date: Start date for log query
            end_date: End date for log query
            user_filter: Filter logs for specific user
            tenant_filter: Filter logs for specific tenant
            event_types: Filter by specific event types
            event_categories: Filter by event categories
            severity_levels: Filter by severity levels
            success_filter: Filter by success/failure
            resource_type: Filter by resource type
            limit: Maximum number of records to return
            offset: Number of records to skip
            justification: Justification for accessing logs (required for sensitive data)
            ip_address: IP address of requester
            
        Returns:
            Dictionary with logs and metadata
        """
        try:
            # Log the query request
            query_start = datetime.utcnow()

            # Build base query
            query = self.db.query(AuditLog)

            # Apply filters
            if start_date:
                query = query.filter(AuditLog.timestamp >= start_date)
            if end_date:
                query = query.filter(AuditLog.timestamp <= end_date)
            if user_filter:
                query = query.filter(AuditLog.user_id == user_filter)
            if tenant_filter:
                query = query.filter(AuditLog.tenant_id == tenant_filter)
            if event_types:
                query = query.filter(AuditLog.event_type.in_(event_types))
            if event_categories:
                query = query.filter(AuditLog.event_category.in_(event_categories))
            if severity_levels:
                query = query.filter(AuditLog.severity.in_(severity_levels))
            if success_filter is not None:
                query = query.filter(AuditLog.success == success_filter)
            if resource_type:
                query = query.filter(AuditLog.resource_type == resource_type)

            # Check for sensitive data access
            sensitive_query = query.filter(AuditLog.is_sensitive == True)
            has_sensitive = sensitive_query.count() > 0

            # Get total count before pagination
            total_count = query.count()

            # Apply pagination and ordering
            logs = query.order_by(desc(AuditLog.timestamp)).offset(offset).limit(limit).all()

            # Calculate query duration
            query_duration = int((datetime.utcnow() - query_start).total_seconds() * 1000)

            # Create query tracking record
            await self._log_audit_query(
                requester_id=requester_id,
                query_type="audit_log_query",
                start_date=start_date,
                end_date=end_date,
                user_filter=user_filter,
                tenant_filter=tenant_filter,
                event_types=event_types,
                records_returned=len(logs),
                query_duration_ms=query_duration,
                requires_approval=has_sensitive,
                justification=justification,
                ip_address=ip_address
            )

            # Convert logs to dictionaries for response
            log_dicts = []
            for log in logs:
                log_dict = {
                    "id": str(log.id),
                    "timestamp": log.timestamp.isoformat(),
                    "event_type": log.event_type,
                    "event_category": log.event_category,
                    "severity": log.severity,
                    "user_id": str(log.user_id) if log.user_id else None,
                    "tenant_id": str(log.tenant_id) if log.tenant_id else None,
                    "resource_type": log.resource_type,
                    "resource_id": str(log.resource_id) if log.resource_id else None,
                    "action": log.action,
                    "success": log.success,
                    "details": log.get_sanitized_details(),
                    "is_sensitive": log.is_sensitive
                }

                # Include additional fields for authorized users
                if not log.is_sensitive or has_sensitive:
                    log_dict.update({
                        "ip_address_hash": log.ip_address_hash,
                        "user_agent": log.user_agent,
                        "request_id": log.request_id,
                        "error_code": log.error_code,
                        "error_message": log.error_message,
                        "duration_ms": log.duration_ms,
                        "compliance_tags": log.compliance_tags
                    })

                log_dicts.append(log_dict)

            return {
                "logs": log_dicts,
                "total_count": total_count,
                "returned_count": len(logs),
                "offset": offset,
                "limit": limit,
                "has_sensitive_data": has_sensitive,
                "query_duration_ms": query_duration
            }

        except Exception as e:
            logger.error(
                "Failed to query audit logs",
                requester_id=str(requester_id),
                error=str(e)
            )
            raise

    async def cleanup_expired_logs(self, batch_size: int = 1000) -> int:
        """
        Clean up audit logs that have passed their retention date.
        
        Args:
            batch_size: Number of logs to process in each batch
            
        Returns:
            Number of logs cleaned up
        """
        try:
            cleaned_count = 0

            while True:
                # Get batch of expired logs
                expired_logs = (
                    self.db.query(AuditLog)
                    .filter(
                        AuditLog.retention_date.isnot(None),
                        AuditLog.retention_date <= datetime.utcnow()
                    )
                    .limit(batch_size)
                    .all()
                )

                if not expired_logs:
                    break

                # Delete expired logs
                for log in expired_logs:
                    self.db.delete(log)
                    cleaned_count += 1

                self.db.commit()

                logger.debug(
                    "Audit log cleanup batch completed",
                    batch_size=len(expired_logs),
                    total_cleaned=cleaned_count
                )

            if cleaned_count > 0:
                logger.info(
                    "Audit log cleanup completed",
                    cleaned_count=cleaned_count
                )

            return cleaned_count

        except Exception as e:
            self.db.rollback()
            logger.error(
                "Audit log cleanup failed",
                error=str(e)
            )
            raise

    def _get_event_category(self, event_type: AuthAuditEvent) -> AuditCategory:
        """Determine the category for an audit event type."""
        event_str = event_type.value

        if event_str.startswith('auth.'):
            return AuditCategory.AUTH
        elif event_str.startswith('user.'):
            return AuditCategory.USER
        elif event_str.startswith('security.'):
            return AuditCategory.SECURITY
        elif event_str.startswith('system.'):
            return AuditCategory.SYSTEM
        elif 'tenant' in event_str:
            return AuditCategory.TENANT
        elif 'admin' in event_str:
            return AuditCategory.ADMIN
        else:
            return AuditCategory.DATA

    def _sanitize_details(self, details: dict[str, Any]) -> dict[str, Any]:
        """Sanitize event details to remove PII and sensitive data."""
        if not details:
            return {}

        sanitized = details.copy()

        # Remove or redact sensitive fields
        sensitive_patterns = [
            'password', 'secret', 'token', 'key', 'auth', 'credential',
            'ssn', 'social_security', 'credit_card', 'card_number',
            'phone', 'email_raw', 'ip_address'
        ]

        for key in list(sanitized.keys()):
            if any(pattern in key.lower() for pattern in sensitive_patterns):
                sanitized[key] = '[REDACTED]'

        return sanitized

    async def _calculate_retention_date(
        self,
        event_type: AuthAuditEvent,
        event_category: AuditCategory,
        severity: AuditSeverity,
        compliance_tags: list[str]
    ) -> datetime:
        """Calculate retention date based on retention policies."""
        try:
            # Get applicable retention policies
            policies = (
                self.db.query(AuditLogRetentionPolicy)
                .filter(AuditLogRetentionPolicy.is_active == True)
                .all()
            )

            # Find the most specific applicable policy
            applicable_policy = None
            for policy in policies:
                if policy.applies_to_event(event_type.value, event_category.value, severity.value, compliance_tags):
                    applicable_policy = policy
                    break

            # Use default policy if no specific policy found
            if not applicable_policy:
                default_policy = (
                    self.db.query(AuditLogRetentionPolicy)
                    .filter(AuditLogRetentionPolicy.is_default == True)
                    .first()
                )
                if default_policy:
                    applicable_policy = default_policy

            # Calculate retention date
            retention_days = applicable_policy.retention_days if applicable_policy else self._default_retention_days
            return datetime.utcnow() + timedelta(days=retention_days)

        except Exception as e:
            logger.warning(
                "Failed to calculate retention date, using default",
                event_type=event_type.value,
                error=str(e)
            )
            return datetime.utcnow() + timedelta(days=self._default_retention_days)

    def _is_sensitive_event(self, event_type: AuthAuditEvent, severity: AuditSeverity) -> bool:
        """Determine if an event contains sensitive information."""
        sensitive_events = {
            AuthAuditEvent.LOGIN_FAILED,
            AuthAuditEvent.SUSPICIOUS_LOGIN,
            AuthAuditEvent.MULTIPLE_FAILED_LOGINS,
            AuthAuditEvent.SESSION_HIJACK_DETECTED,
            AuthAuditEvent.PRIVILEGE_ESCALATION,
            AuthAuditEvent.DATA_EXPORT,
            AuthAuditEvent.ACCOUNT_DELETION_REQUESTED,
            AuthAuditEvent.ADMIN_ACTION
        }

        return event_type in sensitive_events or severity == AuditSeverity.CRITICAL

    async def _log_audit_query(
        self,
        requester_id: UUID,
        query_type: str,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        user_filter: UUID | None = None,
        tenant_filter: UUID | None = None,
        event_types: list[str] | None = None,
        records_returned: int | None = None,
        query_duration_ms: int | None = None,
        requires_approval: bool = False,
        justification: str | None = None,
        ip_address: str | None = None
    ) -> None:
        """Log audit log query for compliance tracking."""
        try:
            ip_hash = None
            if ip_address:
                ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()

            query_log = AuditLogQuery(
                query_type=query_type,
                start_date=start_date,
                end_date=end_date,
                user_filter=user_filter,
                tenant_filter=tenant_filter,
                event_types=event_types or [],
                requested_by=requester_id,
                ip_address_hash=ip_hash,
                justification=justification,
                records_returned=records_returned,
                query_duration_ms=query_duration_ms,
                requires_approval=requires_approval
            )

            self.db.add(query_log)
            self.db.commit()

        except Exception as e:
            logger.warning(
                "Failed to log audit query",
                requester_id=str(requester_id),
                error=str(e)
            )


# Convenience functions for common audit events
async def log_login_success(
    audit_service: AuthAuditService,
    user_id: UUID,
    tenant_id: UUID,
    session_id: UUID,
    ip_address: str | None = None,
    user_agent: str | None = None,
    login_method: str = "sso"
) -> AuditLog:
    """Log successful login event."""
    return await audit_service.log_auth_event(
        event_type=AuthAuditEvent.LOGIN_SUCCESS,
        user_id=user_id,
        tenant_id=tenant_id,
        session_id=session_id,
        action="login",
        details={"login_method": login_method},
        severity=AuditSeverity.INFO,
        ip_address=ip_address,
        user_agent=user_agent,
        success=True
    )


async def log_permission_denied(
    audit_service: AuthAuditService,
    user_id: UUID,
    tenant_id: UUID,
    resource_type: str,
    resource_id: UUID | None = None,
    required_permission: str = None,
    ip_address: str | None = None
) -> AuditLog:
    """Log permission denied event."""
    return await audit_service.log_auth_event(
        event_type=AuthAuditEvent.PERMISSION_DENIED,
        user_id=user_id,
        tenant_id=tenant_id,
        resource_type=resource_type,
        resource_id=resource_id,
        action="access",
        details={"required_permission": required_permission},
        severity=AuditSeverity.WARNING,
        ip_address=ip_address,
        success=False
    )


async def log_tenant_switch(
    audit_service: AuthAuditService,
    user_id: UUID,
    from_tenant_id: UUID,
    to_tenant_id: UUID,
    session_id: UUID,
    ip_address: str | None = None
) -> AuditLog:
    """Log tenant switch event."""
    return await audit_service.log_auth_event(
        event_type=AuthAuditEvent.TENANT_SWITCHED,
        user_id=user_id,
        tenant_id=to_tenant_id,
        session_id=session_id,
        action="switch",
        details={
            "from_tenant_id": str(from_tenant_id),
            "to_tenant_id": str(to_tenant_id)
        },
        severity=AuditSeverity.INFO,
        ip_address=ip_address,
        success=True
    )
