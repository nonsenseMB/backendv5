"""
Request context middleware for FastAPI.
Sets up request context for logging, auditing, and tracking.
"""
from uuid import UUID

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from src.core.context import (
    RequestContext,
    UserContext,
    clear_request_context,
    clear_user_context,
    create_request_id,
    set_request_context,
    set_tenant_context,
    set_user_context,
)
from src.core.logging import get_logger

logger = get_logger(__name__)


class RequestContextMiddleware(BaseHTTPMiddleware):
    """
    Middleware to set up request context for each request.
    
    This middleware should run AFTER authentication middleware
    to have access to user information in request.state.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        """Process the request and set up context."""
        # Generate request ID
        request_id = request.headers.get("X-Request-ID", create_request_id())

        # Extract user information from request state (set by auth middleware)
        user_id = getattr(request.state, "user_id", None)
        tenant_id = getattr(request.state, "tenant_id", None)
        session_id = getattr(request.state, "session_id", None)
        permissions = getattr(request.state, "permissions", [])
        groups = getattr(request.state, "groups", [])

        # Extract request metadata
        ip_address = self._get_client_ip(request)
        user_agent = request.headers.get("User-Agent")
        device_id = request.headers.get("X-Device-ID")
        api_version = request.headers.get("X-API-Version", "v1")

        # Create request context
        request_context = RequestContext(
            request_id=request_id,
            user_id=user_id or "anonymous",
            tenant_id=tenant_id or "default",
            session_id=session_id or "no-session",
            permissions=permissions,
            groups=groups,
            ip_address=ip_address,
            user_agent=user_agent,
            device_id=device_id,
            api_version=api_version,
            method=request.method,
            path=str(request.url.path),
            query_params=dict(request.query_params),
        )

        # Set request context
        set_request_context(request_context)

        # Set tenant context if available
        if tenant_id:
            set_tenant_context(tenant_id)

        # Set user context if authenticated
        if user_id and user_id != "anonymous":
            user_context = await self._create_user_context(request)
            if user_context:
                set_user_context(user_context)

        # Add request ID to response headers
        request.state.request_id = request_id

        # Log request start
        logger.info(
            "Request started",
            request_id=request_id,
            method=request.method,
            path=str(request.url.path),
            user_id=user_id,
            tenant_id=tenant_id,
            ip_address=ip_address
        )

        try:
            # Process request
            response = await call_next(request)

            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id

            # Log request completion
            logger.info(
                "Request completed",
                request_id=request_id,
                status_code=response.status_code,
                method=request.method,
                path=str(request.url.path)
            )

            return response

        except Exception as e:
            # Log request failure
            logger.error(
                "Request failed",
                request_id=request_id,
                method=request.method,
                path=str(request.url.path),
                error=str(e),
                exc_info=True
            )
            raise

        finally:
            # Clear context
            clear_request_context()
            clear_user_context()

    def _get_client_ip(self, request: Request) -> str | None:
        """
        Extract client IP address from request.
        
        Checks X-Forwarded-For and X-Real-IP headers for proxy scenarios.
        """
        # Check X-Forwarded-For header (comma-separated list of IPs)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in the chain
            return forwarded_for.split(",")[0].strip()

        # Check X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        # Fall back to direct client IP
        if request.client:
            return request.client.host

        return None

    async def _create_user_context(self, request: Request) -> UserContext | None:
        """
        Create user context from request state.
        
        This assumes the auth middleware has populated request.state
        with user information.
        """
        user_id = getattr(request.state, "user_id", None)
        if not user_id:
            return None

        try:
            # Get user information from request state (populated by auth middleware)
            # In a real implementation, you might fetch additional user data from DB
            user_context = UserContext(
                user_id=UUID(user_id),
                email=getattr(request.state, "user_email", f"user-{user_id}@example.com"),
                username=getattr(request.state, "username", None),
                full_name=getattr(request.state, "full_name", None),
                is_active=True,  # User must be active to pass auth
                is_verified=getattr(request.state, "is_verified", True),
                permissions=getattr(request.state, "permissions", []),
                groups=getattr(request.state, "groups", []),
                auth_provider=getattr(request.state, "auth_provider", "internal"),
                external_id=getattr(request.state, "external_id", None),
            )

            # Add tenant roles if available
            tenant_id = getattr(request.state, "tenant_id", None)
            tenant_role = getattr(request.state, "tenant_role", None)
            if tenant_id and tenant_role:
                user_context.tenant_roles[str(tenant_id)] = tenant_role

            return user_context

        except Exception as e:
            logger.warning(
                "Failed to create user context",
                user_id=user_id,
                error=str(e)
            )
            return None


async def request_context_middleware(request: Request, call_next):
    """
    Function-based middleware for request context.
    Can be used as @app.middleware("http") decorator.
    """
    middleware = RequestContextMiddleware(None)
    return await middleware.dispatch(request, call_next)
