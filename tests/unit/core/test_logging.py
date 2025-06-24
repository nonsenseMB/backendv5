"""Tests for the logging system."""
from unittest.mock import MagicMock, patch

from src.core.context import (
    RequestContext,
    clear_request_context,
    create_request_id,
    get_request_context,
    set_request_context,
)
from src.core.logging.audit import AuditEventType, AuditSeverity, log_audit_event, log_data_access, log_login_attempt
from src.core.logging.filters import PIIRedactionFilter


class TestPIIRedactionFilter:
    """Test PII redaction functionality."""

    def test_email_redaction(self):
        """Test email address redaction."""
        filter_instance = PIIRedactionFilter()

        test_data = {
            "message": "User email is test@example.com",
            "user_info": {"email": "admin@company.org"}
        }

        result = filter_instance(None, None, test_data)

        # Should contain [EMAIL] tag with hash
        assert "[EMAIL]" in result["message"]
        assert "[EMAIL]" in result["user_info"]["email"]
        assert "test@example.com" not in str(result)
        assert "admin@company.org" not in str(result)

    def test_ip_address_redaction(self):
        """Test IP address redaction."""
        filter_instance = PIIRedactionFilter()

        test_data = {
            "client_ip": "192.168.1.100",
            "ipv6": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        }

        result = filter_instance(None, None, test_data)

        assert "[IPv4]" in result["client_ip"]
        assert "[IPv6]" in result["ipv6"]

    def test_api_key_redaction(self):
        """Test API key and token redaction."""
        filter_instance = PIIRedactionFilter()

        test_data = {
            "authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "api_key": "sk_12345678901234567890abcdefghijklmnop",  # Matches sk_[20+ chars]
            "header": "X-API-Key: abc123def456789012345678901234567890"  # Matches header pattern
        }

        result = filter_instance(None, None, test_data)

        assert "[TOKEN]" in result["authorization"]
        assert "[API_KEY]" in result["api_key"]
        assert "[API_KEY]" in result["header"]

    def test_phone_number_redaction(self):
        """Test phone number redaction."""
        filter_instance = PIIRedactionFilter()

        test_data = {
            "phone": "+49 123 456 7890",  # Simpler format
            "mobile": "0123 456 7890"     # With spaces to match pattern
        }

        result = filter_instance(None, None, test_data)

        assert "[PHONE]" in result["phone"]
        assert "[PHONE]" in result["mobile"]

    def test_pseudonymization_mode(self):
        """Test pseudonymization instead of redaction."""
        filter_instance = PIIRedactionFilter(
            enable_hashing=True,
            hash_salt="test_salt"
        )

        test_data = {"email": "test@example.com"}

        result = filter_instance(None, None, test_data)

        # Should contain [EMAIL] with hash
        assert "[EMAIL]" in result["email"]
        assert result["email"] != "test@example.com"
        # Hash should be consistent
        assert ":" in result["email"]  # Format: [EMAIL]:hash

    def test_nested_data_redaction(self):
        """Test redaction in nested structures."""
        filter_instance = PIIRedactionFilter()

        test_data = {
            "users": [
                {"name": "John", "email": "john@example.com"},
                {"name": "Jane", "email": "jane@example.com"}
            ],
            "metadata": {
                "admin_contact": "admin@company.com",
                "server_ip": "10.0.0.1"
            }
        }

        result = filter_instance(None, None, test_data)

        assert "[EMAIL]" in result["users"][0]["email"]
        assert "[EMAIL]" in result["users"][1]["email"]
        assert "[EMAIL]" in result["metadata"]["admin_contact"]
        assert "[IPv4]" in result["metadata"]["server_ip"]


class TestRequestContext:
    """Test request context management."""

    def test_context_storage_and_retrieval(self):
        """Test storing and retrieving context."""
        context = RequestContext(
            tenant_id="tenant_1",
            request_id="req_123",
            user_id="user_456"
        )

        set_request_context(context)
        retrieved = get_request_context()

        assert retrieved is not None
        assert retrieved.tenant_id == "tenant_1"
        assert retrieved.request_id == "req_123"
        assert retrieved.user_id == "user_456"

    def test_context_isolation(self):
        """Test that context is isolated per thread/async context."""
        context1 = RequestContext(tenant_id="tenant_1")
        context2 = RequestContext(tenant_id="tenant_2")

        set_request_context(context1)
        assert get_request_context().tenant_id == "tenant_1"

        set_request_context(context2)
        assert get_request_context().tenant_id == "tenant_2"

    def test_context_clearing(self):
        """Test context clearing."""
        context = RequestContext(user_id="test_user")
        set_request_context(context)

        assert get_request_context() is not None

        clear_request_context()
        assert get_request_context() is None

    def test_request_id_generation(self):
        """Test request ID generation."""
        req_id1 = create_request_id()
        req_id2 = create_request_id()

        assert req_id1 != req_id2
        assert len(req_id1) == 36  # UUID4 length with hyphens
        assert len(req_id2) == 36


class TestAuditLogging:
    """Test audit logging functionality."""

    @patch('src.core.logging.audit.structlog.get_logger')
    def test_audit_event_logging(self, mock_get_logger):
        """Test basic audit event logging."""
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger

        log_audit_event(
            event_type=AuditEventType.USER_LOGIN,
            user_id="test_user",
            details={"ip_address": "192.168.1.1"},
            severity=AuditSeverity.MEDIUM
        )

        # Verify logger was called
        mock_get_logger.assert_called_with("audit")
        mock_logger.info.assert_called_once()

        # Check the logged data
        call_args = mock_logger.info.call_args
        assert call_args[0][0] == "Audit event"

        logged_data = call_args[1]
        assert logged_data["audit_event"] is True
        assert logged_data["event_type"] == "USER_LOGIN"
        assert logged_data["user_id"] == "test_user"
        assert logged_data["severity"] == "MEDIUM"
        assert "timestamp" in logged_data

    @patch('src.core.logging.audit.structlog.get_logger')
    def test_login_attempt_logging(self, mock_get_logger):
        """Test login attempt logging."""
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger

        # Test successful login
        log_login_attempt(
            user_id="test_user",
            success=True,
            ip_address="192.168.1.1"
        )

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[1]
        assert call_args["event_type"] == "USER_LOGIN"
        assert call_args["severity"] == "MEDIUM"

    @patch('src.core.logging.audit.structlog.get_logger')
    def test_failed_login_logging(self, mock_get_logger):
        """Test failed login attempt logging."""
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger

        # Test failed login
        log_login_attempt(
            user_id="test_user",
            success=False,
            ip_address="192.168.1.1"
        )

        # Failed logins should be logged as warnings (HIGH severity)
        mock_logger.warning.assert_called_once()
        call_args = mock_logger.warning.call_args[1]
        assert call_args["event_type"] == "LOGIN_FAILED"
        assert call_args["severity"] == "HIGH"

    @patch('src.core.logging.audit.structlog.get_logger')
    def test_data_access_logging(self, mock_get_logger):
        """Test data access logging."""
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger

        log_data_access(
            user_id="test_user",
            table_name="users",
            operation="SELECT",
            record_id="123",
            affected_fields=["name", "email"]
        )

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[1]
        assert call_args["resource"] == "users"
        assert call_args["action"] == "SELECT"
        assert call_args["record_id"] == "123"
        assert call_args["affected_fields"] == ["name", "email"]

    @patch('src.core.logging.audit.structlog.get_logger')
    def test_critical_severity_logging(self, mock_get_logger):
        """Test that critical events are logged as errors."""
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger

        log_audit_event(
            event_type=AuditEventType.DATA_ERASURE_REQUEST,
            user_id="admin",
            severity=AuditSeverity.CRITICAL
        )

        # Critical events should be logged as errors
        mock_logger.error.assert_called_once()
        call_args = mock_logger.error.call_args[1]
        assert call_args["severity"] == "CRITICAL"
