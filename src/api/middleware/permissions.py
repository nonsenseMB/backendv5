"""
Permission checking middleware for automatic route-based permission validation.
Implements the permission middleware from task-132.
"""

import re
from collections.abc import Callable

from fastapi import HTTPException, Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware

from ...core.auth.permissions import PermissionChecker
from ...core.logging import get_logger
from ...infrastructure.database.session import get_db

logger = get_logger(__name__)


# Route permission mapping with pattern matching support
ROUTE_PERMISSIONS = {
    # Authentication routes (no permissions needed)
    ("POST", "/api/v1/auth/token"): None,
    ("POST", "/api/v1/auth/device/challenge"): None,
    ("POST", "/api/v1/auth/device/verify"): None,
    ("POST", "/api/v1/auth/device/register"): None,
    ("POST", "/api/v1/auth/certificate/validate"): None,

    # Permission management
    ("GET", "/api/v1/permissions/roles"): "role.read",
    ("POST", "/api/v1/permissions/roles"): "role.create",
    ("POST", "/api/v1/permissions/users/.+/roles"): "role.assign",
    ("DELETE", "/api/v1/permissions/users/.+/roles/.+"): "role.remove",
    ("POST", "/api/v1/permissions/resource"): "permission.grant",
    ("DELETE", "/api/v1/permissions/resource"): "permission.revoke",
    ("POST", "/api/v1/permissions/check"): None,  # Anyone can check their own permissions
    ("GET", "/api/v1/permissions/users/me"): None,  # Anyone can see their own permissions
    ("GET", "/api/v1/permissions/users/.+"): "user.read",

    # User profile endpoints (self-service)
    ("GET", "/api/v1/users/me"): None,  # Anyone can view their own profile
    ("PUT", "/api/v1/users/me"): None,  # Anyone can update their own profile
    ("DELETE", "/api/v1/users/me"): None,  # Anyone can request account deletion
    ("GET", "/api/v1/users/me/preferences"): None,  # Anyone can view their own preferences
    ("PUT", "/api/v1/users/me/preferences"): None,  # Anyone can update their own preferences
    ("GET", "/api/v1/users/me/preferences/.*"): None,  # Specific preference endpoints
    ("PUT", "/api/v1/users/me/preferences/.*"): None,  # Specific preference endpoints
    ("GET", "/api/v1/users/me/tenants"): None,  # Anyone can see their tenant memberships
    ("GET", "/api/v1/users/me/tenant/current"): None,  # Anyone can see current tenant
    ("POST", "/api/v1/users/me/tenant/switch"): None,  # Anyone can switch tenants they belong to
    ("GET", "/api/v1/users/me/tenant/available"): None,  # Anyone can see available tenants

    # Session management endpoints (self-service)
    ("GET", "/api/v1/users/me/sessions"): None,  # Anyone can view their own sessions
    ("GET", "/api/v1/users/me/sessions/current"): None,  # Anyone can view current session
    ("DELETE", "/api/v1/users/me/sessions/.+"): None,  # Anyone can terminate their own sessions
    ("POST", "/api/v1/users/me/sessions/terminate-all"): None,  # Anyone can terminate all their sessions
    ("GET", "/api/v1/users/me/sessions/statistics"): None,  # Anyone can view their session stats
    ("POST", "/api/v1/users/me/sessions/cleanup-expired"): None,  # Anyone can cleanup their expired sessions

    # Future conversation routes
    ("POST", "/api/v1/conversations"): "conversation.create",
    ("GET", "/api/v1/conversations"): "conversation.read",
    ("GET", "/api/v1/conversations/.+"): "conversation.read",
    ("PUT", "/api/v1/conversations/.+"): "conversation.update",
    ("DELETE", "/api/v1/conversations/.+"): "conversation.delete",

    # Future document routes
    ("POST", "/api/v1/documents"): "document.create",
    ("GET", "/api/v1/documents"): "document.read",
    ("GET", "/api/v1/documents/.+"): "document.read",
    ("PUT", "/api/v1/documents/.+"): "document.update",
    ("DELETE", "/api/v1/documents/.+"): "document.delete",

    # Future agent routes
    ("POST", "/api/v1/agents"): "agent.create",
    ("GET", "/api/v1/agents"): "agent.read",
    ("GET", "/api/v1/agents/.+"): "agent.read",
    ("PUT", "/api/v1/agents/.+"): "agent.update",
    ("DELETE", "/api/v1/agents/.+"): "agent.delete",

    # Future team routes
    ("POST", "/api/v1/teams"): "team.create",
    ("GET", "/api/v1/teams"): "team.read",
    ("GET", "/api/v1/teams/.+"): "team.read",
    ("PUT", "/api/v1/teams/.+"): "team.update",
    ("DELETE", "/api/v1/teams/.+"): "team.delete",

    # Future user management routes
    ("GET", "/api/v1/users"): "user.read",
    ("GET", "/api/v1/users/.+"): "user.read",
    ("PUT", "/api/v1/users/.+"): "user.update",
    ("DELETE", "/api/v1/users/.+"): "user.delete",
}


def get_route_permission(method: str, path: str) -> str | None:
    """
    Get required permission for a route using pattern matching.
    
    Args:
        method: HTTP method
        path: Request path
        
    Returns:
        Required permission or None if no permission needed
    """
    for (route_method, route_pattern), permission in ROUTE_PERMISSIONS.items():
        if method == route_method:
            # Use regex for pattern matching
            if re.match(f"^{route_pattern}$", path):
                return permission

    return None


class PermissionMiddleware(BaseHTTPMiddleware):
    """
    Middleware for automatic permission checking based on route patterns.
    """

    def __init__(self, app, bypass_routes: set | None = None):
        super().__init__(app)
        # Routes that bypass permission checking (public routes)
        self.bypass_routes = bypass_routes or {
            "/",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/health",
            "/health/simple"
        }

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Check permissions for the requested route.
        """
        # Skip permission check for bypass routes
        if self._should_bypass_permission_check(request):
            return await call_next(request)

        # Extract required permission from route
        permission = get_route_permission(request.method, request.url.path)

        if permission:
            # Check if user has required permission
            await self._check_route_permission(request, permission)

        # Continue to next middleware/endpoint
        return await call_next(request)

    def _should_bypass_permission_check(self, request: Request) -> bool:
        """Check if the route should bypass permission checking."""
        path = request.url.path

        # Check exact matches for bypass routes
        if path in self.bypass_routes:
            return True

        # Check specific prefix matches only for documentation
        doc_prefixes = ["/docs", "/redoc"]
        for prefix in doc_prefixes:
            if path.startswith(prefix):
                return True

        return False

    async def _check_route_permission(self, request: Request, permission: str) -> None:
        """Check if the user has the required permission for the route."""
        try:
            # Get user and tenant from request state (set by auth middleware)
            user_id = getattr(request.state, "user_id", None)
            tenant_id = getattr(request.state, "tenant_id", None)

            if not user_id or not tenant_id:
                logger.warning(
                    "Missing user or tenant context in permission check",
                    path=request.url.path,
                    method=request.method,
                    permission=permission
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )

            # Get database session
            db_generator = get_db()
            db = next(db_generator)

            try:
                checker = PermissionChecker(db)

                # Extract resource type from permission if needed
                resource_type = None
                if "." in permission:
                    resource_type = permission.split(".")[0]

                has_permission = await checker.check_permission(
                    user_id=user_id,
                    tenant_id=tenant_id,
                    permission=permission,
                    resource_type=resource_type
                )

                if not has_permission:
                    logger.warning(
                        "Route permission denied",
                        user_id=str(user_id),
                        tenant_id=str(tenant_id),
                        path=request.url.path,
                        method=request.method,
                        permission=permission
                    )
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Insufficient permissions. Required: {permission}"
                    )

                logger.debug(
                    "Route permission granted",
                    user_id=str(user_id),
                    tenant_id=str(tenant_id),
                    path=request.url.path,
                    method=request.method,
                    permission=permission
                )

            finally:
                # Close the database session
                db.close()

        except HTTPException:
            raise
        except Exception as e:
            logger.error(
                "Error in permission check",
                error=str(e),
                path=request.url.path,
                method=request.method,
                permission=permission
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Permission check failed"
            )


async def permission_middleware(request: Request, call_next: Callable) -> Response:
    """
    Standalone permission middleware function.
    Alternative to the class-based middleware.
    """
    middleware = PermissionMiddleware(None)
    return await middleware.dispatch(request, call_next)
