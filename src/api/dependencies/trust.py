"""Trust-based policy dependencies for FastAPI endpoints."""
from typing import Optional
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status

from src.core.auth.trust_manager import trust_manager
from src.core.logging import get_logger
from src.infrastructure.database.models.auth import User, UserDevice

logger = get_logger(__name__)


def get_device_policy(request: Request) -> dict:
    """
    Get security policy based on current device trust score.
    
    Returns:
        Policy dictionary with security settings
        
    Raises:
        HTTPException: If no device context found
    """
    # Get device ID from request state
    if not hasattr(request.state, "device_id"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No device context found"
        )
    
    # Get trust score from request state
    trust_score = getattr(request.state, "device_trust_score", 0)
    
    # Get policy based on trust score
    policy = trust_manager.get_device_policy(trust_score)
    
    logger.debug(
        "Retrieved device policy",
        device_id=request.state.device_id,
        trust_score=trust_score,
        trust_level=policy["trust_level"]
    )
    
    return policy


def require_high_trust(policy: dict = Depends(get_device_policy)) -> dict:
    """
    Require high trust device for sensitive operations.
    
    Args:
        policy: Device policy
        
    Returns:
        Policy if high trust
        
    Raises:
        HTTPException: If device doesn't have high trust
    """
    if policy["trust_level"] != "high":
        logger.warning(
            "High trust required but device has lower trust",
            trust_level=policy["trust_level"],
            trust_score=policy["trust_score"]
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This operation requires a high trust device"
        )
    
    return policy


def require_medium_trust(policy: dict = Depends(get_device_policy)) -> dict:
    """
    Require at least medium trust device.
    
    Args:
        policy: Device policy
        
    Returns:
        Policy if medium or high trust
        
    Raises:
        HTTPException: If device has low trust
    """
    if policy["trust_level"] == "low":
        logger.warning(
            "Medium trust required but device has low trust",
            trust_score=policy["trust_score"]
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This operation requires at least a medium trust device"
        )
    
    return policy


def check_sensitive_operation_allowed(
    policy: dict = Depends(get_device_policy)
) -> bool:
    """
    Check if sensitive operations are allowed.
    
    Args:
        policy: Device policy
        
    Returns:
        True if allowed
        
    Raises:
        HTTPException: If not allowed
    """
    if not policy.get("allow_sensitive_operations", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sensitive operations not allowed with current device trust level"
        )
    
    return True


def check_api_key_generation_allowed(
    policy: dict = Depends(get_device_policy)
) -> bool:
    """
    Check if API key generation is allowed.
    
    Args:
        policy: Device policy
        
    Returns:
        True if allowed
        
    Raises:
        HTTPException: If not allowed
    """
    if not policy.get("allow_api_key_generation", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key generation requires a high trust device"
        )
    
    return True


def get_session_limits(policy: dict = Depends(get_device_policy)) -> dict:
    """
    Get session limits based on device trust.
    
    Args:
        policy: Device policy
        
    Returns:
        Session limits dictionary
    """
    return {
        "timeout_minutes": policy.get("session_timeout_minutes", 30),
        "max_duration_minutes": policy.get("max_session_duration_minutes", 480),
        "max_concurrent_sessions": policy.get("max_concurrent_sessions", 1),
        "require_mfa": policy.get("require_mfa", True),
        "trust_level": policy["trust_level"]
    }


async def enforce_concurrent_session_limit(
    request: Request,
    user: User,
    policy: dict = Depends(get_device_policy)
) -> None:
    """
    Enforce concurrent session limit based on trust.
    
    Args:
        request: FastAPI request
        user: Current user
        policy: Device policy
        
    Raises:
        HTTPException: If session limit exceeded
    """
    max_sessions = policy.get("max_concurrent_sessions", 1)
    
    # Get current session count from session service
    from src.infrastructure.auth.session_manager import get_session_manager
    
    session_manager = await get_session_manager()
    active_sessions = await session_manager.get_user_sessions(str(user.id))
    
    # Exclude current session from count
    current_session_id = getattr(request.state, "session_id", None)
    active_count = sum(
        1 for session in active_sessions
        if session.get("session_id") != current_session_id
    )
    
    if active_count >= max_sessions:
        logger.warning(
            "Concurrent session limit exceeded",
            user_id=str(user.id),
            active_sessions=active_count,
            max_allowed=max_sessions,
            trust_level=policy["trust_level"]
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Maximum {max_sessions} concurrent sessions allowed for {policy['trust_level']} trust devices"
        )


def check_continuous_verification_required(
    policy: dict = Depends(get_device_policy)
) -> bool:
    """
    Check if continuous verification is required.
    
    Args:
        policy: Device policy
        
    Returns:
        True if continuous verification required
    """
    return policy.get("require_continuous_verification", False)


class TrustBasedRateLimit:
    """Rate limiting based on device trust level."""
    
    def __init__(
        self,
        high_trust_limit: int = 1000,
        medium_trust_limit: int = 100,
        low_trust_limit: int = 10,
        window_seconds: int = 3600
    ):
        """
        Initialize rate limiter.
        
        Args:
            high_trust_limit: Requests per window for high trust
            medium_trust_limit: Requests per window for medium trust
            low_trust_limit: Requests per window for low trust
            window_seconds: Time window in seconds
        """
        self.limits = {
            "high": high_trust_limit,
            "medium": medium_trust_limit,
            "low": low_trust_limit
        }
        self.window_seconds = window_seconds
    
    async def check_rate_limit(
        self,
        request: Request,
        policy: dict = Depends(get_device_policy)
    ) -> None:
        """
        Check rate limit based on trust level.
        
        Args:
            request: FastAPI request
            policy: Device policy
            
        Raises:
            HTTPException: If rate limit exceeded
        """
        trust_level = policy["trust_level"]
        limit = self.limits.get(trust_level, self.limits["low"])
        
        # Get device ID for rate limiting key
        device_id = getattr(request.state, "device_id", "unknown")
        key = f"rate_limit:{device_id}:{request.url.path}"
        
        # Check rate limit using Redis
        from src.infrastructure.cache import get_redis_client
        
        try:
            redis_client = await get_redis_client()
            
            # Increment counter
            current_count = await redis_client.incr(key)
            
            # Set expiry on first request
            if current_count == 1:
                await redis_client.expire(key, self.window_seconds)
            
            # Check if limit exceeded
            if current_count > limit:
                logger.warning(
                    "Rate limit exceeded",
                    device_id=device_id,
                    trust_level=trust_level,
                    current_count=current_count,
                    limit=limit
                )
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded. Trust level '{trust_level}' allows {limit} requests per {self.window_seconds} seconds"
                )
            
            logger.debug(
                "Rate limit check passed",
                device_id=device_id,
                trust_level=trust_level,
                current_count=current_count,
                limit=limit,
                window_seconds=self.window_seconds
            )
            
        except HTTPException:
            raise
        except Exception as e:
            # Don't fail on rate limit errors
            logger.error(
                "Rate limit check failed",
                error=str(e),
                device_id=device_id
            )