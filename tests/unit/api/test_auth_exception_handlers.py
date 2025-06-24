"""
Tests for authentication exception handlers.

Verifies that exceptions are properly handled, logged,
and converted to appropriate HTTP responses.
"""

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock, AsyncMock
import json

from src.api.exceptions.auth_handlers import (
    register_auth_exception_handlers,
    handle_authentication_error,
    handle_invalid_token_error,
    handle_insufficient_permissions_error,
    handle_tenant_access_denied_error,
    handle_authentik_error
)
from src.core.auth.exceptions import (
    AuthenticationError,
    InvalidTokenError,
    TokenExpiredError,
    InsufficientPermissionsError,
    TenantAccessDeniedError,
    AuthErrorCode
)
from src.infrastructure.auth.exceptions import (
    AuthentikConnectionError,
    AuthentikAuthenticationError,
    AuthentikTimeoutError,
    AuthentikValidationError
)


# Create test app
app = FastAPI()
register_auth_exception_handlers(app)


# Test endpoints that raise exceptions
@app.get("/test/invalid-token")
async def raise_invalid_token():
    raise InvalidTokenError("Test invalid token")


@app.get("/test/token-expired")
async def raise_token_expired():
    raise TokenExpiredError("Test token expired")


@app.get("/test/insufficient-permissions")
async def raise_insufficient_permissions():
    raise InsufficientPermissionsError(
        message="Test permission denied",
        required_permission="admin:write"
    )


@app.get("/test/tenant-access-denied")
async def raise_tenant_access_denied():
    raise TenantAccessDeniedError(
        message="Test tenant access denied",
        tenant_id="tenant-123"
    )


@app.get("/test/authentik-connection")
async def raise_authentik_connection():
    raise AuthentikConnectionError("Connection failed")


@app.get("/test/authentik-auth")
async def raise_authentik_auth():
    raise AuthentikAuthenticationError("Auth failed")


@app.get("/test/authentik-timeout")
async def raise_authentik_timeout():
    raise AuthentikTimeoutError("Request timeout")


@app.get("/test/authentik-validation")
async def raise_authentik_validation():
    raise AuthentikValidationError("Validation failed")


client = TestClient(app)


class TestAuthExceptionHandlers:
    """Test authentication exception handlers."""
    
    @patch('src.api.exceptions.auth_handlers.logger')
    @patch('src.api.exceptions.auth_handlers.log_audit_event')
    @patch('src.api.exceptions.auth_handlers.get_request_context')
    def test_invalid_token_handler(self, mock_context, mock_audit, mock_logger):
        """Test invalid token exception handling."""
        mock_context.return_value = MagicMock(user_id="user-123", tenant_id="tenant-456")
        
        response = client.get("/test/invalid-token")
        
        assert response.status_code == 401
        data = response.json()
        assert data["error"] == AuthErrorCode.TOKEN_INVALID
        assert data["message"] == "Test invalid token"
        
        # Verify logging
        mock_logger.warning.assert_called()
        mock_audit.assert_called_once()
        audit_call = mock_audit.call_args[1]
        assert audit_call["event_type"].value == "login_failed"
        assert audit_call["severity"].value == "high"
        assert audit_call["details"]["reason"] == "invalid_token"
    
    @patch('src.api.exceptions.auth_handlers.logger')
    def test_token_expired_handler(self, mock_logger):
        """Test token expired exception handling."""
        response = client.get("/test/token-expired")
        
        assert response.status_code == 401
        data = response.json()
        assert data["error"] == AuthErrorCode.TOKEN_EXPIRED
        assert data["message"] == "Test token expired"
        
        # Verify logging
        mock_logger.info.assert_called()
    
    @patch('src.api.exceptions.auth_handlers.logger')
    @patch('src.api.exceptions.auth_handlers.log_audit_event')
    @patch('src.api.exceptions.auth_handlers.get_request_context')
    def test_insufficient_permissions_handler(self, mock_context, mock_audit, mock_logger):
        """Test insufficient permissions exception handling."""
        mock_context.return_value = MagicMock(user_id="user-123", tenant_id="tenant-456")
        
        response = client.get("/test/insufficient-permissions")
        
        assert response.status_code == 403
        data = response.json()
        assert data["error"] == AuthErrorCode.INSUFFICIENT_PERMISSIONS
        assert data["message"] == "Test permission denied"
        assert data["details"]["required_permission"] == "admin:write"
        
        # Verify audit logging
        mock_audit.assert_called()
        audit_call = mock_audit.call_args[1]
        assert audit_call["event_type"].value == "permission_change"
        assert audit_call["severity"].value == "medium"
        assert audit_call["details"]["required_permission"] == "admin:write"
        assert audit_call["details"]["action"] == "permission_denied"
    
    @patch('src.api.exceptions.auth_handlers.logger')
    @patch('src.api.exceptions.auth_handlers.log_audit_event')
    @patch('src.api.exceptions.auth_handlers.get_request_context')
    def test_tenant_access_denied_handler(self, mock_context, mock_audit, mock_logger):
        """Test tenant access denied exception handling."""
        mock_context.return_value = MagicMock(user_id="user-123", tenant_id="tenant-789")
        
        response = client.get("/test/tenant-access-denied")
        
        assert response.status_code == 403
        data = response.json()
        assert data["error"] == AuthErrorCode.TENANT_ACCESS_DENIED
        assert data["message"] == "Test tenant access denied"
        assert data["details"]["tenant_id"] == "tenant-123"
        
        # Verify critical audit logging
        mock_logger.error.assert_called()
        mock_audit.assert_called()
        audit_call = mock_audit.call_args[1]
        assert audit_call["event_type"].value == "data_access"
        assert audit_call["severity"].value == "critical"
        assert audit_call["details"]["requested_tenant"] == "tenant-123"
        assert audit_call["details"]["user_tenant"] == "tenant-789"
        assert audit_call["details"]["reason"] == "tenant_access_violation"
        assert audit_call["details"]["action"] == "denied"
    
    @patch('src.api.exceptions.auth_handlers.logger')
    @patch('src.api.exceptions.auth_handlers.log_audit_event')
    def test_authentik_connection_error(self, mock_audit, mock_logger):
        """Test Authentik connection error handling."""
        response = client.get("/test/authentik-connection")
        
        assert response.status_code == 503
        data = response.json()
        assert data["error"] == "auth_service_unavailable"
        assert data["message"] == "Authentication service is temporarily unavailable"
        assert data["details"] == {}  # No internal details exposed
        
        # Verify logging
        mock_logger.error.assert_called()
        mock_audit.assert_called()
        audit_call = mock_audit.call_args[1]
        assert audit_call["event_type"].value == "system_error"
        assert audit_call["details"]["service"] == "authentik"
    
    @patch('src.api.exceptions.auth_handlers.logger')
    def test_authentik_auth_error(self, mock_logger):
        """Test Authentik authentication error handling."""
        response = client.get("/test/authentik-auth")
        
        assert response.status_code == 401
        data = response.json()
        assert data["error"] == AuthErrorCode.INVALID_CREDENTIALS
        assert data["message"] == "Authentication failed"
        assert data["details"] == {}
    
    @patch('src.api.exceptions.auth_handlers.logger')
    def test_authentik_timeout_error(self, mock_logger):
        """Test Authentik timeout error handling."""
        response = client.get("/test/authentik-timeout")
        
        assert response.status_code == 504
        data = response.json()
        assert data["error"] == "auth_service_timeout"
        assert data["message"] == "Authentication service timeout"
        assert data["details"] == {}
    
    @patch('src.api.exceptions.auth_handlers.logger')
    def test_authentik_validation_error(self, mock_logger):
        """Test Authentik validation error handling."""
        response = client.get("/test/authentik-validation")
        
        assert response.status_code == 400
        data = response.json()
        assert data["error"] == "invalid_auth_request"
        assert data["message"] == "Invalid authentication request"
        assert data["details"] == {}
    
    def test_error_response_format(self):
        """Test that all error responses follow consistent format."""
        endpoints = [
            "/test/invalid-token",
            "/test/token-expired",
            "/test/insufficient-permissions",
            "/test/tenant-access-denied",
            "/test/authentik-connection",
            "/test/authentik-auth",
            "/test/authentik-timeout",
            "/test/authentik-validation"
        ]
        
        for endpoint in endpoints:
            response = client.get(endpoint)
            data = response.json()
            
            # Verify response structure
            assert "error" in data
            assert "message" in data
            assert "details" in data
            assert isinstance(data["error"], str)
            assert isinstance(data["message"], str)
            assert isinstance(data["details"], dict)