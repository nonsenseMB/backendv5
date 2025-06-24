"""
Tenant-aware CORS middleware for FastAPI.
Extends standard CORS middleware with per-tenant origin validation.
"""

from fastapi import Request, Response
from fastapi.responses import PlainTextResponse
from starlette.middleware.base import BaseHTTPMiddleware

from src.api.cors.cors import cors_config
from src.core.config import settings
from src.core.context import get_tenant_context
from src.core.logging import get_logger

logger = get_logger(__name__)


class TenantAwareCORSMiddleware(BaseHTTPMiddleware):
    """
    CORS middleware that supports tenant-specific allowed origins.
    
    This middleware checks both global and tenant-specific CORS configurations
    to determine if a request origin should be allowed.
    """

    def __init__(
        self,
        app,
        allow_credentials: bool = True,
        allow_methods: list[str] = None,
        allow_headers: list[str] = None,
        max_age: int = 3600,
        expose_headers: list[str] = None,
    ):
        super().__init__(app)
        self.allow_credentials = allow_credentials
        self.allow_methods = allow_methods or ["*"]
        self.allow_headers = allow_headers or ["*"]
        self.max_age = max_age
        self.expose_headers = expose_headers or []

        # Simple CORS headers for preflight
        self.simple_headers = {
            "Access-Control-Allow-Methods": ", ".join(self.allow_methods),
            "Access-Control-Allow-Headers": ", ".join(self.allow_headers),
            "Access-Control-Max-Age": str(max_age),
        }

        if allow_credentials:
            self.simple_headers["Access-Control-Allow-Credentials"] = "true"

        if expose_headers:
            self.simple_headers["Access-Control-Expose-Headers"] = ", ".join(expose_headers)

    async def dispatch(self, request: Request, call_next) -> Response:
        """Process CORS headers for the request."""
        origin = request.headers.get("origin")

        # No origin header means same-origin request
        if not origin:
            return await call_next(request)

        # Get tenant context if available
        tenant_id = get_tenant_context()

        # Check if origin is allowed
        allowed = await self._is_origin_allowed(origin, tenant_id)

        # Handle preflight requests
        if request.method == "OPTIONS":
            if allowed:
                return self._build_preflight_response(origin)
            else:
                # Return 403 for unauthorized origins
                return PlainTextResponse(
                    "CORS origin not allowed",
                    status_code=403
                )

        # Process actual request
        response = await call_next(request)

        # Add CORS headers if origin is allowed
        if allowed:
            response.headers["Access-Control-Allow-Origin"] = origin

            if self.allow_credentials:
                response.headers["Access-Control-Allow-Credentials"] = "true"

            if self.expose_headers:
                response.headers["Access-Control-Expose-Headers"] = ", ".join(self.expose_headers)

            # Add Vary header to indicate response varies by origin
            vary_header = response.headers.get("Vary", "")
            if vary_header:
                response.headers["Vary"] = f"{vary_header}, Origin"
            else:
                response.headers["Vary"] = "Origin"

        return response

    async def _is_origin_allowed(
        self,
        origin: str,
        tenant_id: str | None
    ) -> bool:
        """
        Check if origin is allowed for the current context.
        
        Args:
            origin: The request origin
            tenant_id: Optional tenant ID from context
            
        Returns:
            True if origin is allowed
        """
        # Validate origin format
        if not cors_config.validate_origin(origin):
            logger.debug("Invalid origin format", origin=origin)
            return False

        # Check global allowed origins
        if cors_config.is_origin_allowed_globally(origin):
            return True

        # Check tenant-specific origins if tenant context exists
        if tenant_id:
            try:
                allowed = await cors_config.is_origin_allowed_for_tenant(origin, tenant_id)
                if allowed:
                    return True
            except Exception as e:
                logger.error(
                    "Error checking tenant CORS",
                    origin=origin,
                    tenant_id=tenant_id,
                    error=str(e)
                )

        return False

    def _build_preflight_response(self, origin: str) -> Response:
        """
        Build response for preflight OPTIONS request.
        
        Args:
            origin: The allowed origin
            
        Returns:
            Preflight response with CORS headers
        """
        headers = dict(self.simple_headers)
        headers["Access-Control-Allow-Origin"] = origin
        headers["Vary"] = "Origin"

        return Response(
            status_code=200,
            headers=headers
        )


async def tenant_aware_cors_middleware(request: Request, call_next):
    """
    Function-based tenant-aware CORS middleware for FastAPI.
    
    Can be used as @app.middleware("http") decorator.
    """
    middleware = TenantAwareCORSMiddleware(
        None,
        allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
        allow_methods=settings.CORS_ALLOW_METHODS,
        allow_headers=settings.CORS_ALLOW_HEADERS,
        max_age=getattr(settings, "CORS_MAX_AGE", 3600),
        expose_headers=getattr(settings, "CORS_EXPOSE_HEADERS", [])
    )

    return await middleware.dispatch(request, call_next)
