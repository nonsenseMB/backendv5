"""
Integration tests for authentication exception handling.

Tests the complete flow of exception handling from endpoint to response.
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from src.main import app
from src.core.auth.exceptions import (
    InvalidTokenError,
    TokenExpiredError,
    InsufficientPermissionsError,
    TenantAccessDeniedError,
    AuthErrorCode
)


# Add test endpoint to the app for testing
@app.get("/test/auth-error")
async def raise_auth_error():
    """Test endpoint that raises authentication errors."""
    raise InvalidTokenError("Integration test error")


client = TestClient(app)


class TestAuthenticationExceptionIntegration:
    """Test authentication exception handling integration."""
    
    def test_exception_handler_registered(self):
        """Test that exception handlers are properly registered."""
        # This test verifies the handlers are registered by triggering an exception
        response = client.get("/test/auth-error")
        
        # Should return 401 with proper error format
        assert response.status_code == 401
        data = response.json()
        assert data["error"] == AuthErrorCode.TOKEN_INVALID
        assert data["message"] == "Integration test error"
        assert "details" in data
    
    @patch('src.core.logging.audit.structlog.get_logger')
    def test_audit_logging_on_auth_failure(self, mock_get_logger):
        """Test that authentication failures trigger audit logs."""
        mock_logger = mock_get_logger.return_value
        
        response = client.get("/test/auth-error")
        
        assert response.status_code == 401
        # Verify audit logger was called
        mock_get_logger.assert_called_with("audit")
        mock_logger.bind.assert_called()
    
    def test_error_response_format_consistency(self):
        """Test that all error responses maintain consistent format."""
        response = client.get("/test/auth-error")
        
        assert response.status_code == 401
        data = response.json()
        
        # Check required fields
        assert "error" in data
        assert "message" in data
        assert "details" in data
        
        # Check types
        assert isinstance(data["error"], str)
        assert isinstance(data["message"], str)
        assert isinstance(data["details"], dict)
    
    def test_request_id_in_error_response(self):
        """Test that request ID is included in error responses."""
        # Send request with custom request ID
        headers = {"X-Request-ID": "test-request-123"}
        response = client.get("/test/auth-error", headers=headers)
        
        assert response.status_code == 401
        # Check response headers for request ID
        assert response.headers.get("X-Request-ID") == "test-request-123"
    
    def test_no_sensitive_info_in_error(self):
        """Test that error responses don't leak sensitive information."""
        response = client.get("/test/auth-error")
        
        assert response.status_code == 401
        data = response.json()
        
        # Ensure no stack traces or internal details
        response_text = str(data).lower()
        assert "traceback" not in response_text
        assert "stack" not in response_text
        assert "file" not in response_text
        assert "line" not in response_text