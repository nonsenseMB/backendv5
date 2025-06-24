"""
Core authentication exceptions for the nAI Backend.

This module defines the authentication exception hierarchy used throughout
the application. These exceptions are designed to provide clear error
messages while maintaining security by not exposing sensitive information.

All exceptions integrate with the logging and audit system for proper
tracking and compliance.
"""

from enum import Enum
from typing import Any


class AuthErrorCode(str, Enum):
    """Authentication error codes for consistent error handling."""

    INVALID_CREDENTIALS = "invalid_credentials"
    TOKEN_EXPIRED = "token_expired"
    TOKEN_INVALID = "token_invalid"
    TOKEN_MISSING = "token_missing"
    INSUFFICIENT_PERMISSIONS = "insufficient_permissions"
    TENANT_ACCESS_DENIED = "tenant_access_denied"
    DEVICE_NOT_TRUSTED = "device_not_trusted"
    SESSION_EXPIRED = "session_expired"
    MFA_REQUIRED = "mfa_required"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_DISABLED = "account_disabled"


class AuthenticationError(Exception):
    """
    Base exception for all authentication-related errors.
    
    This serves as the base class for all authentication exceptions,
    providing a consistent interface for error handling.
    
    Attributes:
        message: Human-readable error message (security-conscious)
        error_code: Machine-readable error code for client handling
        status_code: HTTP status code for API responses
        details: Additional error details (optional)
    """

    def __init__(
        self,
        message: str,
        error_code: AuthErrorCode = AuthErrorCode.INVALID_CREDENTIALS,
        status_code: int = 401,
        details: dict[str, Any] | None = None
    ):
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.details = details or {}
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        """Convert exception to dictionary for API responses."""
        return {
            "error": self.error_code,
            "message": self.message,
            "details": self.details
        }


class InvalidTokenError(AuthenticationError):
    """Raised when JWT validation fails."""

    def __init__(
        self,
        message: str = "Invalid authentication token",
        details: dict[str, Any] | None = None
    ):
        super().__init__(
            message=message,
            error_code=AuthErrorCode.TOKEN_INVALID,
            status_code=401,
            details=details
        )


class TokenExpiredError(AuthenticationError):
    """Raised when a token has expired."""

    def __init__(
        self,
        message: str = "Authentication token has expired",
        details: dict[str, Any] | None = None
    ):
        super().__init__(
            message=message,
            error_code=AuthErrorCode.TOKEN_EXPIRED,
            status_code=401,
            details=details
        )


class TokenMissingError(AuthenticationError):
    """Raised when required authentication token is missing."""

    def __init__(
        self,
        message: str = "Authentication token is required",
        details: dict[str, Any] | None = None
    ):
        super().__init__(
            message=message,
            error_code=AuthErrorCode.TOKEN_MISSING,
            status_code=401,
            details=details
        )


class InsufficientPermissionsError(AuthenticationError):
    """Raised when user lacks required permissions."""

    def __init__(
        self,
        message: str = "Insufficient permissions to access this resource",
        required_permission: str | None = None,
        details: dict[str, Any] | None = None
    ):
        if required_permission:
            details = details or {}
            details["required_permission"] = required_permission

        super().__init__(
            message=message,
            error_code=AuthErrorCode.INSUFFICIENT_PERMISSIONS,
            status_code=403,
            details=details
        )


class TenantAccessDeniedError(AuthenticationError):
    """Raised when tenant isolation is violated."""

    def __init__(
        self,
        message: str = "Access denied to this tenant",
        tenant_id: str | None = None,
        details: dict[str, Any] | None = None
    ):
        if tenant_id:
            details = details or {}
            details["tenant_id"] = tenant_id

        super().__init__(
            message=message,
            error_code=AuthErrorCode.TENANT_ACCESS_DENIED,
            status_code=403,
            details=details
        )


class DeviceNotTrustedError(AuthenticationError):
    """Raised when device authentication fails."""

    def __init__(
        self,
        message: str = "Device is not trusted",
        device_id: str | None = None,
        details: dict[str, Any] | None = None
    ):
        if device_id:
            details = details or {}
            details["device_id"] = device_id

        super().__init__(
            message=message,
            error_code=AuthErrorCode.DEVICE_NOT_TRUSTED,
            status_code=403,
            details=details
        )


class SessionExpiredError(AuthenticationError):
    """Raised when a user session has expired."""

    def __init__(
        self,
        message: str = "Session has expired",
        details: dict[str, Any] | None = None
    ):
        super().__init__(
            message=message,
            error_code=AuthErrorCode.SESSION_EXPIRED,
            status_code=401,
            details=details
        )


class MFARequiredError(AuthenticationError):
    """Raised when multi-factor authentication is required."""

    def __init__(
        self,
        message: str = "Multi-factor authentication required",
        mfa_methods: list | None = None,
        details: dict[str, Any] | None = None
    ):
        if mfa_methods:
            details = details or {}
            details["mfa_methods"] = mfa_methods

        super().__init__(
            message=message,
            error_code=AuthErrorCode.MFA_REQUIRED,
            status_code=403,
            details=details
        )


class AccountLockedException(AuthenticationError):
    """Raised when user account is locked."""

    def __init__(
        self,
        message: str = "Account is locked",
        unlock_time: str | None = None,
        details: dict[str, Any] | None = None
    ):
        if unlock_time:
            details = details or {}
            details["unlock_time"] = unlock_time

        super().__init__(
            message=message,
            error_code=AuthErrorCode.ACCOUNT_LOCKED,
            status_code=403,
            details=details
        )


class AccountDisabledException(AuthenticationError):
    """Raised when user account is disabled."""

    def __init__(
        self,
        message: str = "Account is disabled",
        reason: str | None = None,
        details: dict[str, Any] | None = None
    ):
        if reason:
            details = details or {}
            details["reason"] = reason

        super().__init__(
            message=message,
            error_code=AuthErrorCode.ACCOUNT_DISABLED,
            status_code=403,
            details=details
        )
