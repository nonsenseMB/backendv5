from typing import Any


class AuthentikError(Exception):
    """Base exception for all Authentik-related errors"""

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        details: dict[str, Any] | None = None
    ):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}


class AuthentikConnectionError(AuthentikError):
    """Raised when connection to Authentik fails"""
    pass


class AuthentikAuthenticationError(AuthentikError):
    """Raised when authentication with Authentik fails"""
    pass


class AuthentikAPIError(AuthentikError):
    """Raised when Authentik API returns an error"""
    pass


class AuthentikTimeoutError(AuthentikError):
    """Raised when request to Authentik times out"""
    pass


class AuthentikValidationError(AuthentikError):
    """Raised when data validation fails"""
    pass


class AuthentikTokenExpiredError(AuthentikValidationError):
    """Raised when JWT token has expired"""
    pass
