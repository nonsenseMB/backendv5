"""
Session activity tracking middleware.
Automatically logs user activities for session monitoring and security.
"""

import time
from collections.abc import Callable
from uuid import UUID

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from ...core.auth.session_manager import SessionManager
from ...core.logging import get_logger
from ...infrastructure.database.session import get_db

logger = get_logger(__name__)


class SessionTrackingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for automatic session activity tracking.
    Logs API calls, tenant switches, and other session activities.
    """

    def __init__(self, app, track_all_requests: bool = True):
        super().__init__(app)
        self.track_all_requests = track_all_requests

        # Routes that should always be tracked regardless of settings
        self.always_track_routes = {
            "/api/v1/auth/",
            "/api/v1/users/me/tenant/switch",
            "/api/v1/users/me/sessions/",
            "/api/v1/permissions/"
        }

        # Routes to exclude from tracking (performance/noise reduction)
        self.exclude_routes = {
            "/docs",
            "/redoc",
            "/openapi.json",
            "/health",
            "/favicon.ico",
            "/static/"
        }

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Track session activity for the request."""
        start_time = time.time()

        # Check if we should track this request
        if not self._should_track_request(request):
            return await call_next(request)

        # Get user and session context
        user_id = getattr(request.state, "user_id", None)
        session_id = getattr(request.state, "session_id", None)

        if not user_id or not session_id:
            # No session context available, skip tracking
            return await call_next(request)

        # Process the request
        response = await call_next(request)

        # Calculate request duration
        duration_ms = int((time.time() - start_time) * 1000)

        # Log the activity asynchronously (don't block the response)
        try:
            await self._log_session_activity(
                request=request,
                response=response,
                user_id=UUID(user_id),
                session_id=UUID(session_id),
                duration_ms=duration_ms
            )
        except Exception as e:
            # Don't let activity logging errors affect the main request
            logger.warning(
                "Failed to log session activity",
                user_id=str(user_id),
                session_id=str(session_id),
                path=request.url.path,
                error=str(e)
            )

        return response

    def _should_track_request(self, request: Request) -> bool:
        """Determine if this request should be tracked."""
        path = request.url.path

        # Skip excluded routes
        for exclude_path in self.exclude_routes:
            if path.startswith(exclude_path):
                return False

        # Always track certain routes
        for always_track_path in self.always_track_routes:
            if path.startswith(always_track_path):
                return True

        # Track based on global setting
        return self.track_all_requests

    async def _log_session_activity(
        self,
        request: Request,
        response: Response,
        user_id: UUID,
        session_id: UUID,
        duration_ms: int
    ) -> None:
        """Log session activity to database."""
        try:
            # Get database session
            db_generator = get_db()
            db = next(db_generator)

            try:
                session_manager = SessionManager(db)

                # Determine activity type based on request
                activity_type = self._get_activity_type(request)
                activity_category = self._get_activity_category(request)

                # Extract resource information
                resource_type, resource_id = self._extract_resource_info(request)

                # Prepare activity details
                details = {
                    "endpoint": request.url.path,
                    "query_params": dict(request.query_params) if request.query_params else {},
                    "user_agent": request.headers.get("user-agent"),
                    "content_type": request.headers.get("content-type"),
                    "response_size": response.headers.get("content-length")
                }

                # Add tenant switch specific details
                if activity_type == "tenant_switch":
                    details.update(await self._extract_tenant_switch_details(request))

                # Log the activity
                await session_manager._log_session_activity(
                    session_id=session_id,
                    activity_type=activity_type,
                    details=details,
                    endpoint=request.url.path,
                    http_method=request.method,
                    status_code=response.status_code,
                    success=(200 <= response.status_code < 300)
                )

                # Also update session last activity
                try:
                    await session_manager.validate_session(session_id, update_activity=True)
                except Exception:
                    # Session might not exist or be expired, that's ok
                    pass

            finally:
                db.close()

        except Exception as e:
            logger.error(
                "Error in session activity logging",
                user_id=str(user_id),
                session_id=str(session_id),
                path=request.url.path,
                error=str(e)
            )

    def _get_activity_type(self, request: Request) -> str:
        """Determine activity type based on request path and method."""
        path = request.url.path
        method = request.method

        # Specific activity types
        if "/auth/" in path:
            if "token" in path:
                return "auth_token_request"
            elif "device" in path:
                return "device_auth"
            elif "certificate" in path:
                return "certificate_auth"
            return "authentication"

        elif "/tenant/switch" in path:
            return "tenant_switch"

        elif "/sessions/" in path:
            if method == "DELETE":
                return "session_termination"
            elif "terminate-all" in path:
                return "bulk_session_termination"
            return "session_management"

        elif "/conversations" in path:
            if method == "POST":
                return "conversation_create"
            elif method == "GET":
                return "conversation_read"
            elif method in ["PUT", "PATCH"]:
                return "conversation_update"
            elif method == "DELETE":
                return "conversation_delete"
            return "conversation_access"

        elif "/documents" in path:
            if method == "POST":
                return "document_create"
            elif method == "GET":
                return "document_read"
            elif method in ["PUT", "PATCH"]:
                return "document_update"
            elif method == "DELETE":
                return "document_delete"
            return "document_access"

        elif "/permissions" in path:
            return "permission_management"

        elif "/users/me" in path:
            if "/preferences" in path:
                return "preference_update" if method in ["PUT", "PATCH"] else "preference_access"
            return "profile_update" if method in ["PUT", "PATCH"] else "profile_access"

        # Default activity type
        return f"api_call_{method.lower()}"

    def _get_activity_category(self, request: Request) -> str:
        """Determine activity category for grouping and filtering."""
        path = request.url.path

        if "/auth/" in path:
            return "auth"
        elif "/permissions" in path:
            return "admin"
        elif "/sessions" in path:
            return "security"
        elif "/users/me" in path:
            return "profile"
        elif "/tenant" in path:
            return "tenant"
        elif any(resource in path for resource in ["/conversations", "/documents", "/agents"]):
            return "data"
        else:
            return "general"

    def _extract_resource_info(self, request: Request) -> tuple[str, str]:
        """Extract resource type and ID from request path."""
        path = request.url.path

        # Try to extract resource information from common patterns
        if "/conversations/" in path:
            parts = path.split("/conversations/")
            if len(parts) > 1 and parts[1]:
                resource_id = parts[1].split("/")[0]
                return "conversation", resource_id
            return "conversation", None

        elif "/documents/" in path:
            parts = path.split("/documents/")
            if len(parts) > 1 and parts[1]:
                resource_id = parts[1].split("/")[0]
                return "document", resource_id
            return "document", None

        elif "/agents/" in path:
            parts = path.split("/agents/")
            if len(parts) > 1 and parts[1]:
                resource_id = parts[1].split("/")[0]
                return "agent", resource_id
            return "agent", None

        elif "/sessions/" in path:
            parts = path.split("/sessions/")
            if len(parts) > 1 and parts[1]:
                resource_id = parts[1].split("/")[0]
                return "session", resource_id
            return "session", None

        return None, None

    async def _extract_tenant_switch_details(self, request: Request) -> dict:
        """Extract additional details for tenant switch operations."""
        details = {}

        try:
            # Try to get tenant information from request body or state
            if hasattr(request.state, "tenant_id"):
                details["target_tenant_id"] = str(request.state.tenant_id)

            # Could also parse request body for tenant switch requests
            # But we'd need to be careful not to consume the body stream

        except Exception as e:
            logger.debug("Could not extract tenant switch details", error=str(e))

        return details


async def session_tracking_middleware(request: Request, call_next: Callable) -> Response:
    """
    Standalone session tracking middleware function.
    Alternative to the class-based middleware.
    """
    middleware = SessionTrackingMiddleware(None, track_all_requests=True)
    return await middleware.dispatch(request, call_next)
