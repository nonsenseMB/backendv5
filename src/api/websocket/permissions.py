"""
WebSocket permission system.
Handles permission validation for WebSocket operations.
"""

from typing import Optional, Dict, Any, Set
from functools import wraps
import asyncio
from datetime import datetime

from fastapi import WebSocket

from ...core.logging import get_logger
from ...core.auth.permissions import PermissionChecker
from ...infrastructure.database.session import get_async_session
from ...infrastructure.cache.redis_client import get_redis_client
from .connection_manager import get_connection_manager

logger = get_logger(__name__)


class WebSocketPermissionManager:
    """
    Manages permissions for WebSocket connections.
    Caches permissions and handles validation.
    """
    
    def __init__(self):
        self._permission_cache: Dict[str, Dict[str, Set[str]]] = {}
        self._cache_ttl = 300  # 5 minutes
        self._cache_timestamps: Dict[str, float] = {}
        
    async def check_permission(
        self,
        user_id: str,
        tenant_id: str,
        permission: str
    ) -> bool:
        """
        Check if user has permission.
        
        Args:
            user_id: User identifier
            tenant_id: Tenant identifier
            permission: Required permission
            
        Returns:
            True if permission granted
        """
        # Check cache first
        cache_key = f"{user_id}:{tenant_id}"
        
        if cache_key in self._permission_cache:
            cache_age = asyncio.get_event_loop().time() - self._cache_timestamps.get(cache_key, 0)
            if cache_age < self._cache_ttl:
                permissions = self._permission_cache[cache_key].get("permissions", set())
                return permission in permissions
        
        # Load from database
        try:
            async for db in get_async_session():
                checker = PermissionChecker(db)
                has_permission = await checker.check_permission(
                    user_id=user_id,
                    tenant_id=tenant_id,
                    permission=permission
                )
                
                # Update cache
                if cache_key not in self._permission_cache:
                    self._permission_cache[cache_key] = {"permissions": set()}
                
                if has_permission:
                    self._permission_cache[cache_key]["permissions"].add(permission)
                
                self._cache_timestamps[cache_key] = asyncio.get_event_loop().time()
                
                return has_permission
                
        except Exception as e:
            logger.error(
                "Failed to check permission",
                error=str(e),
                user_id=user_id,
                permission=permission
            )
            return False
    
    async def check_resource_permission(
        self,
        user_id: str,
        tenant_id: str,
        resource_type: str,
        resource_id: str,
        permission: str
    ) -> bool:
        """
        Check resource-specific permission.
        
        Args:
            user_id: User identifier
            tenant_id: Tenant identifier
            resource_type: Type of resource
            resource_id: Resource identifier
            permission: Required permission
            
        Returns:
            True if permission granted
        """
        try:
            async for db in get_async_session():
                checker = PermissionChecker(db)
                has_permission = await checker.check_resource_permission(
                    user_id=user_id,
                    tenant_id=tenant_id,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    permission=permission
                )
                
                logger.debug(
                    "Checked resource permission",
                    user_id=user_id,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    permission=permission,
                    granted=has_permission
                )
                
                return has_permission
                
        except Exception as e:
            logger.error(
                "Failed to check resource permission",
                error=str(e),
                user_id=user_id,
                resource_type=resource_type,
                resource_id=resource_id
            )
            return False
    
    def clear_cache(self, user_id: str, tenant_id: str):
        """Clear permission cache for a user."""
        cache_key = f"{user_id}:{tenant_id}"
        self._permission_cache.pop(cache_key, None)
        self._cache_timestamps.pop(cache_key, None)
    
    def clear_all_cache(self):
        """Clear all permission cache."""
        self._permission_cache.clear()
        self._cache_timestamps.clear()


class WebSocketRateLimiter:
    """
    Rate limiter for WebSocket connections.
    Uses token bucket algorithm for flexible rate limiting.
    """
    
    def __init__(self):
        self.limits = {
            "message.create": (10, 60),      # 10 messages per 60 seconds
            "subscribe": (50, 60),           # 50 subscriptions per 60 seconds
            "unsubscribe": (50, 60),         # 50 unsubscriptions per 60 seconds
            "presence.update": (5, 60),      # 5 presence updates per 60 seconds
            "default": (100, 60)             # 100 general actions per 60 seconds
        }
        self.redis_client = None
        self._local_buckets: Dict[str, Dict[str, Any]] = {}
    
    async def _ensure_redis(self):
        """Ensure Redis client is initialized."""
        if self.redis_client is None:
            self.redis_client = await get_redis_client()
    
    async def check_rate_limit(
        self,
        connection_id: str,
        action: str
    ) -> bool:
        """
        Check if an action is within rate limits.
        
        Args:
            connection_id: Connection identifier
            action: Action name to rate limit
            
        Returns:
            True if within limits, False if rate limited
        """
        limit, window = self.limits.get(action, self.limits["default"])
        
        # Try Redis first for distributed rate limiting
        try:
            await self._ensure_redis()
            
            if self.redis_client:
                key = f"ws_rate:{connection_id}:{action}"
                
                # Use Redis pipeline for atomic operations
                pipe = self.redis_client.pipeline()
                pipe.incr(key)
                pipe.expire(key, window)
                results = await pipe.execute()
                
                current_count = results[0]
                return current_count <= limit
                
        except Exception as e:
            logger.warning(
                "Redis rate limit check failed, falling back to local",
                error=str(e)
            )
        
        # Fallback to local rate limiting
        return self._check_local_rate_limit(connection_id, action, limit, window)
    
    def _check_local_rate_limit(
        self,
        connection_id: str,
        action: str,
        limit: int,
        window: int
    ) -> bool:
        """
        Local rate limit check using token bucket.
        """
        key = f"{connection_id}:{action}"
        current_time = asyncio.get_event_loop().time()
        
        if key not in self._local_buckets:
            self._local_buckets[key] = {
                "tokens": float(limit),
                "last_update": current_time
            }
        
        bucket = self._local_buckets[key]
        
        # Refill tokens based on time elapsed
        time_elapsed = current_time - bucket["last_update"]
        tokens_to_add = time_elapsed * (limit / window)
        bucket["tokens"] = min(limit, bucket["tokens"] + tokens_to_add)
        bucket["last_update"] = current_time
        
        # Check if we have tokens available
        if bucket["tokens"] >= 1:
            bucket["tokens"] -= 1
            return True
        
        return False
    
    def reset_connection(self, connection_id: str):
        """Reset rate limits for a connection."""
        # Clear local buckets
        keys_to_remove = [
            key for key in self._local_buckets
            if key.startswith(f"{connection_id}:")
        ]
        for key in keys_to_remove:
            self._local_buckets.pop(key, None)
    
    async def reset_connection_redis(self, connection_id: str):
        """Reset rate limits in Redis."""
        try:
            await self._ensure_redis()
            
            if self.redis_client:
                pattern = f"ws_rate:{connection_id}:*"
                keys = await self.redis_client.keys(pattern)
                
                if keys:
                    await self.redis_client.delete(*keys)
                    
        except Exception as e:
            logger.error(
                "Failed to reset Redis rate limits",
                error=str(e),
                connection_id=connection_id
            )


# Global instances
_permission_manager: Optional[WebSocketPermissionManager] = None
_rate_limiter: Optional[WebSocketRateLimiter] = None


def get_permission_manager() -> WebSocketPermissionManager:
    """Get singleton permission manager."""
    global _permission_manager
    if _permission_manager is None:
        _permission_manager = WebSocketPermissionManager()
    return _permission_manager


def get_rate_limiter() -> WebSocketRateLimiter:
    """Get singleton rate limiter."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = WebSocketRateLimiter()
    return _rate_limiter