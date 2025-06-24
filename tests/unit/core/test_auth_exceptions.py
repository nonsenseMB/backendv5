"""
Unit tests for authentication exceptions.

Tests the exception hierarchy and error formatting to ensure
consistent and secure error handling.
"""

import pytest

from src.core.auth.exceptions import (
    AuthenticationError,
    InvalidTokenError,
    TokenExpiredError,
    TokenMissingError,
    InsufficientPermissionsError,
    TenantAccessDeniedError,
    DeviceNotTrustedError,
    SessionExpiredError,
    MFARequiredError,
    AccountLockedException,
    AccountDisabledException,
    AuthErrorCode
)


class TestAuthenticationExceptions:
    """Test authentication exception hierarchy."""
    
    def test_base_authentication_error(self):
        """Test base AuthenticationError class."""
        exc = AuthenticationError(
            message="Test error",
            error_code=AuthErrorCode.INVALID_CREDENTIALS,
            status_code=401,
            details={"foo": "bar"}
        )
        
        assert exc.message == "Test error"
        assert exc.error_code == AuthErrorCode.INVALID_CREDENTIALS
        assert exc.status_code == 401
        assert exc.details == {"foo": "bar"}
        
        # Test to_dict method
        error_dict = exc.to_dict()
        assert error_dict["error"] == AuthErrorCode.INVALID_CREDENTIALS
        assert error_dict["message"] == "Test error"
        assert error_dict["details"] == {"foo": "bar"}
    
    def test_invalid_token_error(self):
        """Test InvalidTokenError."""
        exc = InvalidTokenError()
        
        assert exc.message == "Invalid authentication token"
        assert exc.error_code == AuthErrorCode.TOKEN_INVALID
        assert exc.status_code == 401
        
        # Test with custom message
        exc = InvalidTokenError(
            message="Custom invalid token message",
            details={"reason": "signature_verification_failed"}
        )
        assert exc.message == "Custom invalid token message"
        assert exc.details["reason"] == "signature_verification_failed"
    
    def test_token_expired_error(self):
        """Test TokenExpiredError."""
        exc = TokenExpiredError()
        
        assert exc.message == "Authentication token has expired"
        assert exc.error_code == AuthErrorCode.TOKEN_EXPIRED
        assert exc.status_code == 401
    
    def test_token_missing_error(self):
        """Test TokenMissingError."""
        exc = TokenMissingError()
        
        assert exc.message == "Authentication token is required"
        assert exc.error_code == AuthErrorCode.TOKEN_MISSING
        assert exc.status_code == 401
    
    def test_insufficient_permissions_error(self):
        """Test InsufficientPermissionsError."""
        exc = InsufficientPermissionsError()
        
        assert exc.message == "Insufficient permissions to access this resource"
        assert exc.error_code == AuthErrorCode.INSUFFICIENT_PERMISSIONS
        assert exc.status_code == 403
        
        # Test with required permission
        exc = InsufficientPermissionsError(
            required_permission="admin:write"
        )
        assert exc.details["required_permission"] == "admin:write"
    
    def test_tenant_access_denied_error(self):
        """Test TenantAccessDeniedError."""
        exc = TenantAccessDeniedError()
        
        assert exc.message == "Access denied to this tenant"
        assert exc.error_code == AuthErrorCode.TENANT_ACCESS_DENIED
        assert exc.status_code == 403
        
        # Test with tenant_id
        exc = TenantAccessDeniedError(tenant_id="tenant-123")
        assert exc.details["tenant_id"] == "tenant-123"
    
    def test_device_not_trusted_error(self):
        """Test DeviceNotTrustedError."""
        exc = DeviceNotTrustedError()
        
        assert exc.message == "Device is not trusted"
        assert exc.error_code == AuthErrorCode.DEVICE_NOT_TRUSTED
        assert exc.status_code == 403
        
        # Test with device_id
        exc = DeviceNotTrustedError(device_id="device-xyz")
        assert exc.details["device_id"] == "device-xyz"
    
    def test_session_expired_error(self):
        """Test SessionExpiredError."""
        exc = SessionExpiredError()
        
        assert exc.message == "Session has expired"
        assert exc.error_code == AuthErrorCode.SESSION_EXPIRED
        assert exc.status_code == 401
    
    def test_mfa_required_error(self):
        """Test MFARequiredError."""
        exc = MFARequiredError()
        
        assert exc.message == "Multi-factor authentication required"
        assert exc.error_code == AuthErrorCode.MFA_REQUIRED
        assert exc.status_code == 403
        
        # Test with MFA methods
        exc = MFARequiredError(mfa_methods=["totp", "webauthn"])
        assert exc.details["mfa_methods"] == ["totp", "webauthn"]
    
    def test_account_locked_exception(self):
        """Test AccountLockedException."""
        exc = AccountLockedException()
        
        assert exc.message == "Account is locked"
        assert exc.error_code == AuthErrorCode.ACCOUNT_LOCKED
        assert exc.status_code == 403
        
        # Test with unlock time
        exc = AccountLockedException(unlock_time="2024-01-21T10:00:00Z")
        assert exc.details["unlock_time"] == "2024-01-21T10:00:00Z"
    
    def test_account_disabled_exception(self):
        """Test AccountDisabledException."""
        exc = AccountDisabledException()
        
        assert exc.message == "Account is disabled"
        assert exc.error_code == AuthErrorCode.ACCOUNT_DISABLED
        assert exc.status_code == 403
        
        # Test with reason
        exc = AccountDisabledException(reason="Terms violation")
        assert exc.details["reason"] == "Terms violation"
    
    def test_exception_inheritance(self):
        """Test that all exceptions inherit from AuthenticationError."""
        exceptions = [
            InvalidTokenError(),
            TokenExpiredError(),
            TokenMissingError(),
            InsufficientPermissionsError(),
            TenantAccessDeniedError(),
            DeviceNotTrustedError(),
            SessionExpiredError(),
            MFARequiredError(),
            AccountLockedException(),
            AccountDisabledException()
        ]
        
        for exc in exceptions:
            assert isinstance(exc, AuthenticationError)
            assert isinstance(exc, Exception)
            assert hasattr(exc, 'to_dict')
            assert hasattr(exc, 'message')
            assert hasattr(exc, 'error_code')
            assert hasattr(exc, 'status_code')
            assert hasattr(exc, 'details')