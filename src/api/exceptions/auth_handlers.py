"""
FastAPI exception handlers for authentication errors.

This module provides centralized exception handling for authentication-related
errors, ensuring consistent error responses and proper logging/auditing.
"""

from typing import Any

from fastapi import Request, status
from fastapi.responses import JSONResponse

from src.core.auth.exceptions import (
    AuthenticationError,
    AuthErrorCode,
    InsufficientPermissionsError,
    InvalidTokenError,
    TenantAccessDeniedError,
    TokenExpiredError,
)
from src.core.context import get_request_context
from src.core.logging import get_logger
from src.core.logging.audit import AuditEventType, AuditSeverity, log_audit_event
from src.infrastructure.auth.exceptions import (
    AuthentikAPIError,
    AuthentikAuthenticationError,
    AuthentikConnectionError,
    AuthentikError,
    AuthentikTimeoutError,
    AuthentikValidationError,
)

logger = get_logger(__name__)


def create_error_response(
    error_code: str,
    message: str,
    status_code: int,
    details: dict[str, Any] = None
) -> JSONResponse:
    """Create standardized error response."""
    content = {
        "error": error_code,
        "message": message,
        "details": details or {}
    }

    return JSONResponse(
        status_code=status_code,
        content=content
    )


async def handle_authentication_error(
    request: Request,
    exc: AuthenticationError
) -> JSONResponse:
    """
    Handle base authentication errors.
    
    Logs the error and creates appropriate response while ensuring
    no sensitive information is exposed.
    """
    context = get_request_context()

    # Log the authentication error
    logger.warning(
        "Authentication error occurred",
        error_code=exc.error_code,
        status_code=exc.status_code,
        path=str(request.url.path),
        method=request.method,
        details=exc.details
    )

    # Log audit event for security tracking
    log_audit_event(
        event_type=AuditEventType.LOGIN_FAILED,
        severity=AuditSeverity.MEDIUM,
        details={
            "error_code": exc.error_code,
            "path": str(request.url.path),
            "method": request.method,
            "user_id": context.user_id if context else None,
            "tenant_id": context.tenant_id if context else None
        }
    )

    return create_error_response(
        error_code=exc.error_code,
        message=exc.message,
        status_code=exc.status_code,
        details=exc.details
    )


async def handle_invalid_token_error(
    request: Request,
    exc: InvalidTokenError
) -> JSONResponse:
    """Handle invalid token errors with enhanced logging."""
    context = get_request_context()

    logger.warning(
        "Invalid token presented",
        path=str(request.url.path),
        method=request.method
    )

    log_audit_event(
        event_type=AuditEventType.LOGIN_FAILED,
        severity=AuditSeverity.HIGH,
        details={
            "path": str(request.url.path),
            "method": request.method,
            "ip_address": request.client.host if request.client else None,
            "reason": "invalid_token"
        }
    )

    return await handle_authentication_error(request, exc)


async def handle_token_expired_error(
    request: Request,
    exc: TokenExpiredError
) -> JSONResponse:
    """Handle expired token errors."""
    logger.info(
        "Token expired",
        path=str(request.url.path),
        method=request.method
    )

    return await handle_authentication_error(request, exc)


async def handle_insufficient_permissions_error(
    request: Request,
    exc: InsufficientPermissionsError
) -> JSONResponse:
    """Handle permission denied errors with audit logging."""
    context = get_request_context()

    logger.warning(
        "Permission denied",
        path=str(request.url.path),
        method=request.method,
        required_permission=exc.details.get("required_permission"),
        user_id=context.user_id if context else None
    )

    log_audit_event(
        event_type=AuditEventType.PERMISSION_CHANGE,
        severity=AuditSeverity.MEDIUM,
        details={
            "path": str(request.url.path),
            "method": request.method,
            "required_permission": exc.details.get("required_permission"),
            "user_id": context.user_id if context else None,
            "tenant_id": context.tenant_id if context else None,
            "action": "permission_denied"
        }
    )

    return await handle_authentication_error(request, exc)


async def handle_tenant_access_denied_error(
    request: Request,
    exc: TenantAccessDeniedError
) -> JSONResponse:
    """Handle tenant isolation violations with high severity logging."""
    context = get_request_context()

    logger.error(
        "Tenant access violation",
        path=str(request.url.path),
        method=request.method,
        requested_tenant=exc.details.get("tenant_id"),
        user_tenant=context.tenant_id if context else None,
        user_id=context.user_id if context else None
    )

    log_audit_event(
        event_type=AuditEventType.DATA_ACCESS,
        severity=AuditSeverity.CRITICAL,
        details={
            "path": str(request.url.path),
            "method": request.method,
            "requested_tenant": exc.details.get("tenant_id"),
            "user_tenant": context.tenant_id if context else None,
            "user_id": context.user_id if context else None,
            "reason": "tenant_access_violation",
            "action": "denied"
        }
    )

    return await handle_authentication_error(request, exc)


async def handle_authentik_error(
    request: Request,
    exc: AuthentikError
) -> JSONResponse:
    """
    Handle Authentik-specific errors.
    
    Maps Authentik errors to appropriate HTTP responses while
    maintaining security and not exposing internal details.
    """
    logger.error(
        "Authentik error occurred",
        error_type=type(exc).__name__,
        path=str(request.url.path),
        method=request.method,
        details=exc.details
    )

    # Map Authentik errors to appropriate status codes
    if isinstance(exc, AuthentikConnectionError):
        status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        message = "Authentication service is temporarily unavailable"
        error_code = "auth_service_unavailable"
    elif isinstance(exc, AuthentikAuthenticationError):
        status_code = status.HTTP_401_UNAUTHORIZED
        message = "Authentication failed"
        error_code = AuthErrorCode.INVALID_CREDENTIALS
    elif isinstance(exc, AuthentikTimeoutError):
        status_code = status.HTTP_504_GATEWAY_TIMEOUT
        message = "Authentication service timeout"
        error_code = "auth_service_timeout"
    elif isinstance(exc, AuthentikValidationError):
        status_code = status.HTTP_400_BAD_REQUEST
        message = "Invalid authentication request"
        error_code = "invalid_auth_request"
    else:
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        message = "Authentication service error"
        error_code = "auth_service_error"

    # Log audit event for Authentik errors
    log_audit_event(
        event_type=AuditEventType.SYSTEM_ERROR,
        severity=AuditSeverity.HIGH,
        details={
            "error_type": type(exc).__name__,
            "path": str(request.url.path),
            "method": request.method,
            "service": "authentik"
        }
    )

    return create_error_response(
        error_code=error_code,
        message=message,
        status_code=status_code,
        details={}  # Don't expose internal details
    )


def register_auth_exception_handlers(app):
    """
    Register all authentication exception handlers with the FastAPI app.
    
    This function should be called during app initialization to ensure
    all authentication errors are properly handled.
    
    Args:
        app: FastAPI application instance
    """
    # Core authentication exceptions
    app.add_exception_handler(AuthenticationError, handle_authentication_error)
    app.add_exception_handler(InvalidTokenError, handle_invalid_token_error)
    app.add_exception_handler(TokenExpiredError, handle_token_expired_error)
    app.add_exception_handler(InsufficientPermissionsError, handle_insufficient_permissions_error)
    app.add_exception_handler(TenantAccessDeniedError, handle_tenant_access_denied_error)

    # Authentik-specific exceptions
    app.add_exception_handler(AuthentikError, handle_authentik_error)
    app.add_exception_handler(AuthentikConnectionError, handle_authentik_error)
    app.add_exception_handler(AuthentikAuthenticationError, handle_authentik_error)
    app.add_exception_handler(AuthentikAPIError, handle_authentik_error)
    app.add_exception_handler(AuthentikTimeoutError, handle_authentik_error)
    app.add_exception_handler(AuthentikValidationError, handle_authentik_error)

    logger.info("Authentication exception handlers registered")
