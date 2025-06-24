"""
Audit logging middleware for automatic capture of authentication and API events.
Integrates with the comprehensive audit logging system for compliance tracking.
"""

import time
from uuid import UUID, uuid4

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from ...api.dependencies.database import get_db
from ...core.context import get_request_context
from ...core.logging import get_logger
from ...core.logging.auth_audit import AuditSeverity, AuthAuditEvent, AuthAuditService

logger = get_logger(__name__)


class AuditLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for automatic audit logging of API requests and security events.
    Captures request/response data for compliance and security monitoring.
    """

    def __init__(self, app, excluded_paths: list | None = None):
        super().__init__(app)
        self.excluded_paths = excluded_paths or [
            "/health",
            "/metrics",
            "/docs",
            "/openapi.json",
            "/redoc",
            "/favicon.ico"
        ]

    async def dispatch(self, request: Request, call_next):
        # Skip audit logging for excluded paths
        if any(request.url.path.startswith(path) for path in self.excluded_paths):
            return await call_next(request)

        # Skip audit logging for static files and health checks
        if request.url.path.endswith(('.css', '.js', '.png', '.jpg', '.ico')):
            return await call_next(request)

        # Initialize audit context
        start_time = time.time()
        request_id = request.headers.get("X-Request-ID", str(uuid4()))
        ip_address = self._get_client_ip(request)
        user_agent = request.headers.get("User-Agent")

        # Get user context if available
        context = get_request_context()
        user_id = None
        tenant_id = None
        session_id = None

        if context:
            user_id = context.user_id
            tenant_id = context.tenant_id
            session_id = getattr(context, 'session_id', None)

        # Initialize database session for audit logging
        db_session = None
        audit_service = None

        try:
            # Get database session
            db_gen = get_db()
            db_session = next(db_gen)
            audit_service = AuthAuditService(db_session)

            # Determine event type based on request
            event_type = self._determine_event_type(request)

            # Log request start if it's a significant event
            if event_type and self._should_log_request(request):
                await self._log_request_start(
                    audit_service, request, event_type, user_id, tenant_id,
                    session_id, ip_address, user_agent, request_id
                )

            # Process request
            response = await call_next(request)

            # Calculate duration
            duration_ms = int((time.time() - start_time) * 1000)

            # Log response if significant
            if event_type and self._should_log_response(request, response):
                await self._log_request_completion(
                    audit_service, request, response, event_type, user_id, tenant_id,
                    session_id, ip_address, user_agent, request_id, duration_ms
                )

            return response

        except Exception as e:
            # Log the error
            duration_ms = int((time.time() - start_time) * 1000)

            if audit_service:
                try:
                    await self._log_request_error(
                        audit_service, request, e, user_id, tenant_id,
                        session_id, ip_address, user_agent, request_id, duration_ms
                    )
                except Exception as audit_error:
                    logger.error(
                        "Failed to log audit error",
                        error=str(audit_error),
                        original_error=str(e)
                    )

            raise

        finally:
            # Clean up database session
            if db_session:
                try:
                    db_session.close()
                except Exception as cleanup_error:
                    logger.warning(
                        "Failed to close audit database session",
                        error=str(cleanup_error)
                    )

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request headers."""
        # Check for forwarded IP first (proxy scenarios)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in the chain
            return forwarded_for.split(",")[0].strip()

        # Check other common headers
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        # Fall back to direct client IP
        if hasattr(request, "client") and request.client:
            return request.client.host

        return "unknown"

    def _determine_event_type(self, request: Request) -> AuthAuditEvent | None:
        """Determine the audit event type based on the request."""
        method = request.method.upper()
        path = request.url.path.lower()

        # Authentication events
        if "/auth/login" in path:
            return AuthAuditEvent.LOGIN_SUCCESS
        elif "/auth/logout" in path:
            return AuthAuditEvent.LOGOUT
        elif "/auth/token" in path:
            if "refresh" in path:
                return AuthAuditEvent.TOKEN_REFRESHED
            else:
                return AuthAuditEvent.TOKEN_ISSUED
        elif "/auth/device" in path:
            if method == "POST":
                return AuthAuditEvent.DEVICE_REGISTERED
            elif method == "DELETE":
                return AuthAuditEvent.DEVICE_REMOVED
            elif method == "PUT" or method == "PATCH":
                return AuthAuditEvent.DEVICE_UPDATED

        # Permission events
        elif "/permissions" in path or "/roles" in path:
            if method == "POST":
                return AuthAuditEvent.ROLE_CREATED
            elif method == "PUT" or method == "PATCH":
                return AuthAuditEvent.ROLE_UPDATED
            elif method == "DELETE":
                return AuthAuditEvent.ROLE_DELETED

        # Tenant events
        elif "/tenant" in path and "/switch" in path:
            return AuthAuditEvent.TENANT_SWITCHED

        # Session events
        elif "/sessions" in path:
            if method == "POST":
                return AuthAuditEvent.SESSION_CREATED
            elif method == "DELETE":
                return AuthAuditEvent.SESSION_TERMINATED

        # User profile events
        elif "/users/me" in path:
            if method == "PUT" or method == "PATCH":
                return AuthAuditEvent.PROFILE_UPDATED
            elif method == "DELETE":
                return AuthAuditEvent.ACCOUNT_DELETION_REQUESTED
            elif method == "GET":
                return AuthAuditEvent.PROFILE_VIEWED

        # Data export events
        elif "/export" in path or "/download" in path:
            return AuthAuditEvent.DATA_EXPORT

        # Admin actions
        elif "/admin" in path:
            return AuthAuditEvent.ADMIN_ACTION

        # Security events
        elif "/security" in path or "/audit" in path:
            return AuthAuditEvent.SECURITY_CHECK

        return None

    def _should_log_request(self, request: Request) -> bool:
        """Determine if this request should be logged at start."""
        # Log all authentication and authorization requests
        path = request.url.path.lower()

        sensitive_paths = [
            "/auth/", "/permissions", "/roles", "/admin",
            "/security", "/audit", "/users/me"
        ]

        return any(sensitive_path in path for sensitive_path in sensitive_paths)

    def _should_log_response(self, request: Request, response: Response) -> bool:
        """Determine if this response should be logged."""
        # Always log failed requests (4xx, 5xx)
        if response.status_code >= 400:
            return True

        # Log successful sensitive operations
        if self._should_log_request(request):
            return True

        # Log data modification operations
        if request.method.upper() in ["POST", "PUT", "PATCH", "DELETE"]:
            return True

        return False

    async def _log_request_start(
        self,
        audit_service: AuthAuditService,
        request: Request,
        event_type: AuthAuditEvent,
        user_id: UUID | None,
        tenant_id: UUID | None,
        session_id: UUID | None,
        ip_address: str,
        user_agent: str | None,
        request_id: str
    ):
        """Log the start of a significant request."""
        try:
            await audit_service.log_auth_event(
                event_type=event_type,
                user_id=user_id,
                tenant_id=tenant_id,
                session_id=session_id,
                action="request_start",
                details={
                    "method": request.method,
                    "path": request.url.path,
                    "query_params": dict(request.query_params) if request.query_params else None
                },
                severity=AuditSeverity.INFO,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id
            )
        except Exception as e:
            logger.warning(
                "Failed to log request start",
                error=str(e),
                path=request.url.path
            )

    async def _log_request_completion(
        self,
        audit_service: AuthAuditService,
        request: Request,
        response: Response,
        event_type: AuthAuditEvent,
        user_id: UUID | None,
        tenant_id: UUID | None,
        session_id: UUID | None,
        ip_address: str,
        user_agent: str | None,
        request_id: str,
        duration_ms: int
    ):
        """Log the completion of a request."""
        try:
            # Determine success based on status code
            success = 200 <= response.status_code < 400

            # Determine severity based on status code
            if response.status_code >= 500:
                severity = AuditSeverity.CRITICAL
            elif response.status_code >= 400:
                severity = AuditSeverity.WARNING
            else:
                severity = AuditSeverity.INFO

            # Get response size if available
            response_size = None
            content_length = response.headers.get("content-length")
            if content_length:
                try:
                    response_size = int(content_length)
                except ValueError:
                    pass

            await audit_service.log_auth_event(
                event_type=event_type,
                user_id=user_id,
                tenant_id=tenant_id,
                session_id=session_id,
                action="request_complete",
                details={
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code
                },
                severity=severity,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
                success=success,
                duration_ms=duration_ms,
                response_size_bytes=response_size
            )
        except Exception as e:
            logger.warning(
                "Failed to log request completion",
                error=str(e),
                path=request.url.path,
                status_code=response.status_code
            )

    async def _log_request_error(
        self,
        audit_service: AuthAuditService,
        request: Request,
        error: Exception,
        user_id: UUID | None,
        tenant_id: UUID | None,
        session_id: UUID | None,
        ip_address: str,
        user_agent: str | None,
        request_id: str,
        duration_ms: int
    ):
        """Log request errors and exceptions."""
        try:
            await audit_service.log_auth_event(
                event_type=AuthAuditEvent.SECURITY_ALERT,
                user_id=user_id,
                tenant_id=tenant_id,
                session_id=session_id,
                action="request_error",
                details={
                    "method": request.method,
                    "path": request.url.path,
                    "error_type": type(error).__name__
                },
                severity=AuditSeverity.CRITICAL,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
                success=False,
                error_message=str(error),
                duration_ms=duration_ms
            )
        except Exception as audit_error:
            logger.error(
                "Failed to log request error",
                audit_error=str(audit_error),
                original_error=str(error),
                path=request.url.path
            )


class SecurityEventMiddleware(BaseHTTPMiddleware):
    """
    Specialized middleware for detecting and logging security events.
    Monitors for suspicious patterns and potential security threats.
    """

    def __init__(self, app):
        super().__init__(app)
        self.failed_attempts = {}  # In production, use Redis or database
        self.suspicious_ips = set()  # In production, use Redis or database

    async def dispatch(self, request: Request, call_next):
        ip_address = self._get_client_ip(request)

        # Check for suspicious activity before processing request
        await self._check_suspicious_activity(request, ip_address)

        response = await call_next(request)

        # Check for security events after processing
        await self._check_security_events(request, response, ip_address)

        return response

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request headers."""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        if hasattr(request, "client") and request.client:
            return request.client.host

        return "unknown"

    async def _check_suspicious_activity(self, request: Request, ip_address: str):
        """Check for suspicious activity patterns."""
        try:
            # Check for suspicious IP
            if ip_address in self.suspicious_ips:
                await self._log_security_event(
                    request,
                    AuthAuditEvent.SUSPICIOUS_LOGIN,
                    "Request from known suspicious IP",
                    ip_address
                )

            # Check for unusual user agent patterns
            user_agent = request.headers.get("User-Agent", "")
            if self._is_suspicious_user_agent(user_agent):
                await self._log_security_event(
                    request,
                    AuthAuditEvent.SUSPICIOUS_LOGIN,
                    "Suspicious user agent detected",
                    ip_address
                )

            # Check for rapid requests (simple rate limiting detection)
            if self._is_rapid_requests(ip_address):
                await self._log_security_event(
                    request,
                    AuthAuditEvent.MULTIPLE_FAILED_LOGINS,
                    "Rapid requests detected from IP",
                    ip_address
                )

        except Exception as e:
            logger.warning(
                "Failed to check suspicious activity",
                error=str(e),
                ip_address=ip_address
            )

    async def _check_security_events(self, request: Request, response: Response, ip_address: str):
        """Check for security events based on response."""
        try:
            # Track failed authentication attempts
            if response.status_code == 401 and "/auth/" in request.url.path:
                await self._track_failed_attempt(ip_address)

                # Check if this IP has too many failed attempts
                if self._has_too_many_failures(ip_address):
                    await self._log_security_event(
                        request,
                        AuthAuditEvent.MULTIPLE_FAILED_LOGINS,
                        "Multiple failed login attempts detected",
                        ip_address
                    )
                    self.suspicious_ips.add(ip_address)

            # Track forbidden access attempts
            elif response.status_code == 403:
                await self._log_security_event(
                    request,
                    AuthAuditEvent.PERMISSION_DENIED,
                    "Access denied to protected resource",
                    ip_address
                )

            # Track server errors that might indicate attacks
            elif response.status_code >= 500:
                await self._log_security_event(
                    request,
                    AuthAuditEvent.SECURITY_ALERT,
                    "Server error potentially caused by malicious request",
                    ip_address
                )

        except Exception as e:
            logger.warning(
                "Failed to check security events",
                error=str(e),
                ip_address=ip_address
            )

    def _is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Check if user agent appears suspicious."""
        if not user_agent:
            return True

        suspicious_patterns = [
            "bot", "crawler", "spider", "scraper", "scanner",
            "sqlmap", "nikto", "nmap", "burp", "zaproxy"
        ]

        user_agent_lower = user_agent.lower()
        return any(pattern in user_agent_lower for pattern in suspicious_patterns)

    def _is_rapid_requests(self, ip_address: str) -> bool:
        """Check if IP is making rapid requests (simple implementation)."""
        current_time = time.time()

        # Get request times for this IP
        if ip_address not in self.failed_attempts:
            self.failed_attempts[ip_address] = []

        # Add current request time
        self.failed_attempts[ip_address].append(current_time)

        # Keep only recent requests (last minute)
        recent_requests = [
            t for t in self.failed_attempts[ip_address]
            if current_time - t <= 60
        ]
        self.failed_attempts[ip_address] = recent_requests

        # Consider rapid if more than 10 requests per minute
        return len(recent_requests) > 10

    async def _track_failed_attempt(self, ip_address: str):
        """Track failed authentication attempt."""
        current_time = time.time()

        if ip_address not in self.failed_attempts:
            self.failed_attempts[ip_address] = []

        self.failed_attempts[ip_address].append(current_time)

        # Keep only recent failures (last 15 minutes)
        recent_failures = [
            t for t in self.failed_attempts[ip_address]
            if current_time - t <= 900
        ]
        self.failed_attempts[ip_address] = recent_failures

    def _has_too_many_failures(self, ip_address: str) -> bool:
        """Check if IP has too many recent failures."""
        if ip_address not in self.failed_attempts:
            return False

        # Consider suspicious if more than 5 failures in 15 minutes
        return len(self.failed_attempts[ip_address]) > 5

    async def _log_security_event(
        self,
        request: Request,
        event_type: AuthAuditEvent,
        description: str,
        ip_address: str
    ):
        """Log a security event."""
        try:
            # Get database session for logging
            db_gen = get_db()
            db_session = next(db_gen)
            audit_service = AuthAuditService(db_session)

            # Get user context if available
            context = get_request_context()
            user_id = context.user_id if context else None
            tenant_id = context.tenant_id if context else None

            await audit_service.log_auth_event(
                event_type=event_type,
                user_id=user_id,
                tenant_id=tenant_id,
                action="security_detection",
                details={
                    "method": request.method,
                    "path": request.url.path,
                    "description": description,
                    "query_params": dict(request.query_params) if request.query_params else None
                },
                severity=AuditSeverity.WARNING,
                ip_address=ip_address,
                user_agent=request.headers.get("User-Agent"),
                request_id=request.headers.get("X-Request-ID")
            )

            db_session.close()

        except Exception as e:
            logger.error(
                "Failed to log security event",
                error=str(e),
                event_type=event_type.value,
                description=description
            )
