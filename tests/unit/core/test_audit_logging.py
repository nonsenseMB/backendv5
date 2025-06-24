"""
Unit tests for audit logging functionality.
Tests the comprehensive audit logging system including database persistence and retention.
"""

import pytest
from datetime import datetime, timedelta
from uuid import uuid4, UUID
from unittest.mock import Mock, AsyncMock, patch

from sqlalchemy.orm import Session

from src.core.logging.auth_audit import (
    AuthAuditService, AuthAuditEvent, AuditSeverity, AuditCategory,
    log_login_success, log_permission_denied, log_tenant_switch
)
from src.infrastructure.database.models.audit_log import AuditLog, AuditLogRetentionPolicy


class TestAuthAuditService:
    """Test the AuthAuditService class."""
    
    @pytest.fixture
    def mock_db(self):
        """Mock database session."""
        return Mock(spec=Session)
    
    @pytest.fixture
    def audit_service(self, mock_db):
        """Create audit service instance with mocked database."""
        return AuthAuditService(mock_db)
    
    @pytest.mark.asyncio
    async def test_log_auth_event_basic(self, audit_service, mock_db):
        """Test basic audit event logging."""
        user_id = uuid4()
        tenant_id = uuid4()
        session_id = uuid4()
        
        # Mock database operations
        mock_db.add = Mock()
        mock_db.commit = Mock()
        mock_db.refresh = Mock()
        
        # Create mock audit log for return
        mock_audit_log = Mock()
        mock_audit_log.id = uuid4()
        mock_db.refresh.side_effect = lambda obj: setattr(obj, 'id', mock_audit_log.id)
        
        result = await audit_service.log_auth_event(
            event_type=AuthAuditEvent.LOGIN_SUCCESS,
            user_id=user_id,
            tenant_id=tenant_id,
            session_id=session_id,
            action="login",
            details={"login_method": "sso"},
            severity=AuditSeverity.INFO,
            ip_address="192.168.1.1",
            user_agent="TestAgent/1.0",
            success=True
        )
        
        # Verify database operations were called
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()
        mock_db.refresh.assert_called_once()
        
        # Verify the audit log object was created with correct data
        added_log = mock_db.add.call_args[0][0]
        assert added_log.event_type == AuthAuditEvent.LOGIN_SUCCESS.value
        assert added_log.user_id == user_id
        assert added_log.tenant_id == tenant_id
        assert added_log.session_id == session_id
        assert added_log.action == "login"
        assert added_log.success is True
        assert added_log.severity == AuditSeverity.INFO.value
        assert "login_method" in added_log.details
    
    @pytest.mark.asyncio
    async def test_log_auth_event_with_ip_hashing(self, audit_service, mock_db):
        """Test that IP addresses are properly hashed."""
        # Mock database operations
        mock_db.add = Mock()
        mock_db.commit = Mock()
        mock_db.refresh = Mock()
        
        ip_address = "192.168.1.100"
        
        await audit_service.log_auth_event(
            event_type=AuthAuditEvent.LOGIN_SUCCESS,
            ip_address=ip_address
        )
        
        # Verify IP was hashed
        added_log = mock_db.add.call_args[0][0]
        assert added_log.ip_address_hash is not None
        assert added_log.ip_address_hash != ip_address
        assert len(added_log.ip_address_hash) == 64  # SHA-256 hash length
    
    @pytest.mark.asyncio
    async def test_log_auth_event_pii_sanitization(self, audit_service, mock_db):
        """Test that PII is sanitized in event details."""
        # Mock database operations
        mock_db.add = Mock()
        mock_db.commit = Mock()
        mock_db.refresh = Mock()
        
        details_with_pii = {
            "user_email": "test@example.com",
            "password": "secret123",
            "credit_card": "1234-5678-9012-3456",
            "safe_field": "safe_value"
        }
        
        await audit_service.log_auth_event(
            event_type=AuthAuditEvent.LOGIN_SUCCESS,
            details=details_with_pii
        )
        
        # Verify PII was redacted
        added_log = mock_db.add.call_args[0][0]
        assert added_log.details["password"] == "[REDACTED]"
        assert added_log.details["credit_card"] == "[REDACTED]"
        assert added_log.details["safe_field"] == "safe_value"
    
    @pytest.mark.asyncio
    async def test_log_auth_event_error_handling(self, audit_service, mock_db):
        """Test error handling during audit logging."""
        # Mock database to raise exception
        mock_db.add.side_effect = Exception("Database error")
        mock_db.rollback = Mock()
        
        with pytest.raises(Exception, match="Database error"):
            await audit_service.log_auth_event(
                event_type=AuthAuditEvent.LOGIN_SUCCESS
            )
        
        # Verify rollback was called
        mock_db.rollback.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_query_audit_logs_basic(self, audit_service, mock_db):
        """Test basic audit log querying."""
        user_id = uuid4()
        
        # Mock query results
        mock_query = Mock()
        mock_db.query.return_value = mock_query
        mock_query.filter.return_value = mock_query
        mock_query.order_by.return_value = mock_query
        mock_query.offset.return_value = mock_query
        mock_query.limit.return_value = mock_query
        mock_query.count.return_value = 5
        
        # Mock audit log results
        mock_logs = [Mock() for _ in range(3)]
        for i, log in enumerate(mock_logs):
            log.id = uuid4()
            log.timestamp = datetime.utcnow()
            log.event_type = "auth.login.success"
            log.event_category = "auth"
            log.severity = "info"
            log.user_id = user_id
            log.tenant_id = None
            log.resource_type = None
            log.resource_id = None
            log.action = "login"
            log.success = True
            log.is_sensitive = False
            log.get_sanitized_details.return_value = {"method": "sso"}
        
        mock_query.all.return_value = mock_logs
        
        # Mock the audit query logging
        with patch.object(audit_service, '_log_audit_query', new=AsyncMock()):
            result = await audit_service.query_audit_logs(
                requester_id=user_id,
                user_filter=user_id,
                limit=10,
                offset=0
            )
        
        # Verify query structure
        assert result["total_count"] == 5
        assert result["returned_count"] == 3
        assert len(result["logs"]) == 3
        assert result["offset"] == 0
        assert result["limit"] == 10
    
    @pytest.mark.asyncio
    async def test_cleanup_expired_logs(self, audit_service, mock_db):
        """Test cleanup of expired audit logs."""
        # Mock expired logs
        mock_expired_logs = [Mock() for _ in range(3)]
        for log in mock_expired_logs:
            log.id = uuid4()
            log.retention_date = datetime.utcnow() - timedelta(days=1)
        
        # Mock query for expired logs
        mock_query = Mock()
        mock_db.query.return_value = mock_query
        mock_query.filter.return_value = mock_query
        mock_query.limit.return_value = mock_query
        
        # First call returns logs, second call returns empty (no more logs)
        mock_query.all.side_effect = [mock_expired_logs, []]
        
        mock_db.delete = Mock()
        mock_db.commit = Mock()
        
        result = await audit_service.cleanup_expired_logs(batch_size=10)
        
        # Verify cleanup results
        assert result == 3  # 3 logs cleaned up
        assert mock_db.delete.call_count == 3
        assert mock_db.commit.called
    
    def test_get_event_category(self, audit_service):
        """Test event category determination."""
        assert audit_service._get_event_category(AuthAuditEvent.LOGIN_SUCCESS) == AuditCategory.AUTH
        assert audit_service._get_event_category(AuthAuditEvent.PROFILE_UPDATED) == AuditCategory.USER
        assert audit_service._get_event_category(AuthAuditEvent.SUSPICIOUS_LOGIN) == AuditCategory.SECURITY
        assert audit_service._get_event_category(AuthAuditEvent.SYSTEM_START) == AuditCategory.SYSTEM
        assert audit_service._get_event_category(AuthAuditEvent.TENANT_SWITCHED) == AuditCategory.TENANT
    
    def test_is_sensitive_event(self, audit_service):
        """Test sensitive event detection."""
        assert audit_service._is_sensitive_event(AuthAuditEvent.LOGIN_FAILED, AuditSeverity.WARNING) is True
        assert audit_service._is_sensitive_event(AuthAuditEvent.SUSPICIOUS_LOGIN, AuditSeverity.WARNING) is True
        assert audit_service._is_sensitive_event(AuthAuditEvent.LOGIN_SUCCESS, AuditSeverity.CRITICAL) is True
        assert audit_service._is_sensitive_event(AuthAuditEvent.LOGIN_SUCCESS, AuditSeverity.INFO) is False
    
    def test_sanitize_details(self, audit_service):
        """Test PII sanitization in details."""
        details = {
            "user_password": "secret123",
            "api_key": "sk_live_12345",
            "phone_number": "+1-555-123-4567",
            "safe_data": "this is safe"
        }
        
        sanitized = audit_service._sanitize_details(details)
        
        assert sanitized["user_password"] == "[REDACTED]"
        assert sanitized["api_key"] == "[REDACTED]"
        assert sanitized["phone_number"] == "[REDACTED]"
        assert sanitized["safe_data"] == "this is safe"


class TestConvenienceFunctions:
    """Test convenience functions for common audit events."""
    
    @pytest.mark.asyncio
    async def test_log_login_success(self):
        """Test login success convenience function."""
        mock_audit_service = Mock()
        mock_audit_service.log_auth_event = AsyncMock()
        
        user_id = uuid4()
        tenant_id = uuid4()
        session_id = uuid4()
        
        await log_login_success(
            mock_audit_service,
            user_id=user_id,
            tenant_id=tenant_id,
            session_id=session_id,
            ip_address="192.168.1.1",
            user_agent="TestAgent/1.0",
            login_method="sso"
        )
        
        # Verify the audit service was called with correct parameters
        mock_audit_service.log_auth_event.assert_called_once()
        call_args = mock_audit_service.log_auth_event.call_args
        
        assert call_args.kwargs["event_type"] == AuthAuditEvent.LOGIN_SUCCESS
        assert call_args.kwargs["user_id"] == user_id
        assert call_args.kwargs["tenant_id"] == tenant_id
        assert call_args.kwargs["session_id"] == session_id
        assert call_args.kwargs["success"] is True
        assert call_args.kwargs["details"]["login_method"] == "sso"
    
    @pytest.mark.asyncio
    async def test_log_permission_denied(self):
        """Test permission denied convenience function."""
        mock_audit_service = Mock()
        mock_audit_service.log_auth_event = AsyncMock()
        
        user_id = uuid4()
        tenant_id = uuid4()
        resource_id = uuid4()
        
        await log_permission_denied(
            mock_audit_service,
            user_id=user_id,
            tenant_id=tenant_id,
            resource_type="document",
            resource_id=resource_id,
            required_permission="read",
            ip_address="192.168.1.1"
        )
        
        # Verify the audit service was called with correct parameters
        mock_audit_service.log_auth_event.assert_called_once()
        call_args = mock_audit_service.log_auth_event.call_args
        
        assert call_args.kwargs["event_type"] == AuthAuditEvent.PERMISSION_DENIED
        assert call_args.kwargs["user_id"] == user_id
        assert call_args.kwargs["tenant_id"] == tenant_id
        assert call_args.kwargs["resource_type"] == "document"
        assert call_args.kwargs["resource_id"] == resource_id
        assert call_args.kwargs["success"] is False
        assert call_args.kwargs["severity"] == AuditSeverity.WARNING
    
    @pytest.mark.asyncio
    async def test_log_tenant_switch(self):
        """Test tenant switch convenience function."""
        mock_audit_service = Mock()
        mock_audit_service.log_auth_event = AsyncMock()
        
        user_id = uuid4()
        from_tenant_id = uuid4()
        to_tenant_id = uuid4()
        session_id = uuid4()
        
        await log_tenant_switch(
            mock_audit_service,
            user_id=user_id,
            from_tenant_id=from_tenant_id,
            to_tenant_id=to_tenant_id,
            session_id=session_id,
            ip_address="192.168.1.1"
        )
        
        # Verify the audit service was called with correct parameters
        mock_audit_service.log_auth_event.assert_called_once()
        call_args = mock_audit_service.log_auth_event.call_args
        
        assert call_args.kwargs["event_type"] == AuthAuditEvent.TENANT_SWITCHED
        assert call_args.kwargs["user_id"] == user_id
        assert call_args.kwargs["tenant_id"] == to_tenant_id
        assert call_args.kwargs["session_id"] == session_id
        assert call_args.kwargs["success"] is True
        assert call_args.kwargs["details"]["from_tenant_id"] == str(from_tenant_id)
        assert call_args.kwargs["details"]["to_tenant_id"] == str(to_tenant_id)


class TestAuditLogModel:
    """Test the AuditLog database model."""
    
    def test_is_expired(self):
        """Test the is_expired method."""
        # Log with no retention date should not be expired
        log = AuditLog(retention_date=None)
        assert log.is_expired() is False
        
        # Log with future retention date should not be expired
        future_date = datetime.utcnow() + timedelta(days=30)
        log = AuditLog(retention_date=future_date)
        assert log.is_expired() is False
        
        # Log with past retention date should be expired
        past_date = datetime.utcnow() - timedelta(days=1)
        log = AuditLog(retention_date=past_date)
        assert log.is_expired() is True
    
    def test_get_sanitized_details(self):
        """Test the get_sanitized_details method."""
        # Empty details
        log = AuditLog(details=None)
        assert log.get_sanitized_details() == {}
        
        # Details with sensitive data
        sensitive_details = {
            "user_password": "secret123",
            "credit_card_number": "1234-5678-9012-3456",
            "safe_field": "safe_value"
        }
        log = AuditLog(details=sensitive_details)
        sanitized = log.get_sanitized_details()
        
        assert sanitized["user_password"] == "[REDACTED]"
        assert sanitized["credit_card_number"] == "[REDACTED]"
        assert sanitized["safe_field"] == "safe_value"


class TestRetentionPolicy:
    """Test the retention policy functionality."""
    
    def test_applies_to_event_exact_match(self):
        """Test retention policy exact event matching."""
        policy = AuditLogRetentionPolicy(
            event_types=["auth.login.success"],
            event_categories=["auth"],
            severity_levels=["info"],
            compliance_tags=["GDPR"]
        )
        
        # Exact match should apply
        assert policy.applies_to_event(
            "auth.login.success", "auth", "info", ["GDPR"]
        ) is True
        
        # Partial match should not apply
        assert policy.applies_to_event(
            "auth.login.failed", "auth", "info", ["GDPR"]
        ) is False
    
    def test_applies_to_event_empty_criteria(self):
        """Test retention policy with empty criteria (matches all)."""
        policy = AuditLogRetentionPolicy(
            event_types=[],
            event_categories=[],
            severity_levels=[],
            compliance_tags=[]
        )
        
        # Should match any event when criteria are empty
        assert policy.applies_to_event(
            "any.event.type", "any_category", "any_severity", ["any_tag"]
        ) is True
    
    def test_applies_to_event_compliance_tags(self):
        """Test retention policy compliance tag matching."""
        policy = AuditLogRetentionPolicy(
            compliance_tags=["GDPR", "SOX"]
        )
        
        # Should match if any compliance tag overlaps
        assert policy.applies_to_event(
            "event", "category", "severity", ["GDPR", "HIPAA"]
        ) is True
        
        # Should not match if no compliance tags overlap
        assert policy.applies_to_event(
            "event", "category", "severity", ["HIPAA", "PCI"]
        ) is False
        
        # Should not match if event has no compliance tags
        assert policy.applies_to_event(
            "event", "category", "severity", []
        ) is False


class TestEventTypes:
    """Test audit event type definitions."""
    
    def test_auth_events(self):
        """Test authentication event types."""
        assert AuthAuditEvent.LOGIN_SUCCESS.value == "auth.login.success"
        assert AuthAuditEvent.LOGIN_FAILED.value == "auth.login.failed"
        assert AuthAuditEvent.TOKEN_ISSUED.value == "auth.token.issued"
        assert AuthAuditEvent.TOKEN_REFRESHED.value == "auth.token.refreshed"
    
    def test_device_events(self):
        """Test device authentication event types."""
        assert AuthAuditEvent.DEVICE_REGISTERED.value == "auth.device.registered"
        assert AuthAuditEvent.DEVICE_REMOVED.value == "auth.device.removed"
        assert AuthAuditEvent.DEVICE_AUTH_SUCCESS.value == "auth.device.success"
        assert AuthAuditEvent.DEVICE_AUTH_FAILED.value == "auth.device.failed"
    
    def test_security_events(self):
        """Test security event types."""
        assert AuthAuditEvent.SUSPICIOUS_LOGIN.value == "security.suspicious_login"
        assert AuthAuditEvent.MULTIPLE_FAILED_LOGINS.value == "security.multiple_failed_logins"
        assert AuthAuditEvent.PRIVILEGE_ESCALATION.value == "security.privilege_escalation"
        assert AuthAuditEvent.DATA_EXPORT.value == "security.data_export"
    
    def test_severity_levels(self):
        """Test audit severity levels."""
        assert AuditSeverity.INFO.value == "info"
        assert AuditSeverity.WARNING.value == "warning"
        assert AuditSeverity.CRITICAL.value == "critical"
    
    def test_audit_categories(self):
        """Test audit event categories."""
        assert AuditCategory.AUTH.value == "auth"
        assert AuditCategory.DATA.value == "data"
        assert AuditCategory.SECURITY.value == "security"
        assert AuditCategory.SYSTEM.value == "system"
        assert AuditCategory.USER.value == "user"
        assert AuditCategory.TENANT.value == "tenant"