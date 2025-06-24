"""Rate limiting middleware for API endpoints."""
from datetime import datetime
from uuid import UUID

from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from src.core.logging import get_logger
from src.infrastructure.cache import get_redis_client

logger = get_logger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware with Redis backend.
    
    Provides flexible rate limiting based on user, IP, or endpoint.
    """

    def __init__(self, app, default_limits: dict[str, int] | None = None):
        """
        Initialize rate limiter.
        
        Args:
            app: FastAPI application
            default_limits: Default rate limits
        """
        super().__init__(app)

        # Default rate limits (requests per window)
        self.default_limits = default_limits or {
            "requests_per_minute": 60,
            "requests_per_hour": 1000,
            "requests_per_day": 10000
        }

        # Endpoint-specific limits
        self.endpoint_limits = {
            "/api/v1/auth/device-management": {
                "requests_per_minute": 10,
                "requests_per_hour": 100,
                "requests_per_day": 500
            },
            "/api/v1/auth/device": {
                "requests_per_minute": 20,
                "requests_per_hour": 200,
                "requests_per_day": 1000
            },
            "/api/v1/auth/certificates": {
                "requests_per_minute": 5,
                "requests_per_hour": 50,
                "requests_per_day": 200
            }
        }

        # Time windows in seconds
        self.windows = {
            "minute": 60,
            "hour": 3600,
            "day": 86400
        }

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint
    ) -> Response:
        """Process request with rate limiting."""
        # Skip rate limiting for certain paths
        if self._should_skip_rate_limiting(request):
            return await call_next(request)

        try:
            # Get rate limiting key
            limit_key = await self._get_rate_limit_key(request)

            if limit_key:
                # Check rate limits
                await self._check_rate_limits(request, limit_key)

            # Process request
            response = await call_next(request)

            return response

        except HTTPException:
            raise
        except Exception as e:
            logger.error(
                "Rate limiting error",
                path=request.url.path,
                error=str(e),
                exc_info=True
            )
            # Don't fail request on rate limiter errors
            return await call_next(request)

    def _should_skip_rate_limiting(self, request: Request) -> bool:
        """Check if request should skip rate limiting."""
        # Skip for health checks, static files, etc.
        skip_paths = [
            "/health",
            "/metrics",
            "/docs",
            "/redoc",
            "/openapi.json"
        ]

        return any(request.url.path.startswith(path) for path in skip_paths)

    async def _get_rate_limit_key(self, request: Request) -> str | None:
        """Generate rate limiting key for the request."""
        # Prefer user-based limiting
        if hasattr(request.state, "user"):
            user_id = getattr(request.state.user, "id", None)
            if user_id:
                return f"user:{user_id}"

        # Fall back to IP-based limiting
        client_ip = self._get_client_ip(request)
        if client_ip:
            return f"ip:{client_ip}"

        return None

    def _get_client_ip(self, request: Request) -> str | None:
        """Extract client IP address from request."""
        # Check various headers for real IP
        headers_to_check = [
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Client-IP",
            "CF-Connecting-IP"
        ]

        for header in headers_to_check:
            value = request.headers.get(header)
            if value:
                # Take first IP if comma-separated
                return value.split(",")[0].strip()

        # Fall back to direct client
        if request.client:
            return request.client.host

        return None

    async def _check_rate_limits(self, request: Request, limit_key: str):
        """Check rate limits for the request."""
        try:
            redis_client = await get_redis_client()

            # Get limits for this endpoint
            limits = self._get_endpoint_limits(request.url.path)

            # Check each time window
            for window_name, limit in limits.items():
                if window_name.startswith("requests_per_"):
                    window_type = window_name.replace("requests_per_", "")
                    window_seconds = self.windows.get(window_type)

                    if window_seconds:
                        await self._check_window_limit(
                            redis_client=redis_client,
                            limit_key=limit_key,
                            endpoint=request.url.path,
                            window_type=window_type,
                            window_seconds=window_seconds,
                            limit=limit,
                            request=request
                        )

        except Exception as e:
            logger.error(
                "Rate limit check failed",
                limit_key=limit_key,
                path=request.url.path,
                error=str(e)
            )
            # Don't fail on rate limit errors

    def _get_endpoint_limits(self, path: str) -> dict[str, int]:
        """Get rate limits for specific endpoint."""
        # Check for exact match first
        if path in self.endpoint_limits:
            return self.endpoint_limits[path]

        # Check for prefix matches
        for endpoint_pattern, limits in self.endpoint_limits.items():
            if path.startswith(endpoint_pattern):
                return limits

        # Return default limits
        return self.default_limits

    async def _check_window_limit(
        self,
        redis_client,
        limit_key: str,
        endpoint: str,
        window_type: str,
        window_seconds: int,
        limit: int,
        request: Request
    ):
        """Check rate limit for a specific time window."""
        # Create Redis key for this window
        now = datetime.utcnow()
        window_start = self._get_window_start(now, window_type)
        redis_key = f"rate_limit:{limit_key}:{endpoint}:{window_type}:{window_start}"

        # Increment counter
        current_count = await redis_client.incr(redis_key)

        # Set expiry on first request
        if current_count == 1:
            await redis_client.expire(redis_key, window_seconds)

        # Check if limit exceeded
        if current_count > limit:
            # Log rate limit violation
            logger.warning(
                "Rate limit exceeded",
                limit_key=limit_key,
                endpoint=endpoint,
                window_type=window_type,
                current_count=current_count,
                limit=limit,
                client_ip=self._get_client_ip(request)
            )

            # Calculate retry after
            window_end = window_start + window_seconds
            retry_after = window_end - int(now.timestamp())

            # Raise rate limit exception
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
                headers={"Retry-After": str(retry_after)}
            )

        # Add rate limit headers to successful requests
        if hasattr(request.state, "_rate_limit_headers"):
            request.state._rate_limit_headers.update({
                f"X-RateLimit-{window_type.title()}-Limit": str(limit),
                f"X-RateLimit-{window_type.title()}-Remaining": str(max(0, limit - current_count)),
                f"X-RateLimit-{window_type.title()}-Reset": str(window_start + window_seconds)
            })
        else:
            request.state._rate_limit_headers = {
                f"X-RateLimit-{window_type.title()}-Limit": str(limit),
                f"X-RateLimit-{window_type.title()}-Remaining": str(max(0, limit - current_count)),
                f"X-RateLimit-{window_type.title()}-Reset": str(window_start + window_seconds)
            }

    def _get_window_start(self, now: datetime, window_type: str) -> int:
        """Get the start of the current window."""
        timestamp = int(now.timestamp())

        if window_type == "minute":
            return timestamp - (timestamp % 60)
        elif window_type == "hour":
            return timestamp - (timestamp % 3600)
        elif window_type == "day":
            # Start of day in UTC
            start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
            return int(start_of_day.timestamp())

        return timestamp


class DeviceOperationRateLimiter:
    """Specific rate limiter for device operations."""

    def __init__(self):
        """Initialize device operation rate limiter."""
        self.limits = {
            "device_registration": {"per_hour": 5, "per_day": 20},
            "device_removal": {"per_hour": 3, "per_day": 10},
            "device_update": {"per_hour": 10, "per_day": 50},
            "certificate_enrollment": {"per_hour": 2, "per_day": 10}
        }

    async def check_device_operation_limit(
        self,
        user_id: UUID,
        operation: str,
        redis_client = None
    ) -> bool:
        """
        Check if user can perform device operation.
        
        Args:
            user_id: User ID
            operation: Operation type
            redis_client: Redis client (optional)
            
        Returns:
            True if operation is allowed
            
        Raises:
            HTTPException: If rate limit exceeded
        """
        if not redis_client:
            redis_client = await get_redis_client()

        if operation not in self.limits:
            return True  # No limit for unknown operations

        limits = self.limits[operation]
        now = datetime.utcnow()

        # Check hourly limit
        hour_key = f"device_op:{user_id}:{operation}:{now.strftime('%Y%m%d%H')}"
        hour_count = await redis_client.incr(hour_key)
        await redis_client.expire(hour_key, 3600)

        if hour_count > limits["per_hour"]:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Hourly limit exceeded for {operation}. Try again later."
            )

        # Check daily limit
        day_key = f"device_op:{user_id}:{operation}:{now.strftime('%Y%m%d')}"
        day_count = await redis_client.incr(day_key)
        await redis_client.expire(day_key, 86400)

        if day_count > limits["per_day"]:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Daily limit exceeded for {operation}. Try again tomorrow."
            )

        logger.debug(
            "Device operation rate limit check passed",
            user_id=str(user_id),
            operation=operation,
            hour_count=hour_count,
            day_count=day_count
        )

        return True


# Global instance
device_rate_limiter = DeviceOperationRateLimiter()
