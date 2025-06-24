"""
WebSocket middleware for authentication and request processing.
Provides decorators and middleware functions for WebSocket handlers.
"""

from typing import Callable, Optional, Dict, Any
from functools import wraps
import asyncio

from fastapi import WebSocket, WebSocketDisconnect

from ...core.logging import get_logger
from ...core.auth.permissions import PermissionChecker
from ...infrastructure.database.session import get_async_session
from .auth import get_websocket_authenticator
from .connection_manager import get_connection_manager, WebSocketConnection

logger = get_logger(__name__)


class WebSocketRateLimiter:
    """
    Rate limiter for WebSocket connections and messages.
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
        self._buckets: Dict[str, Dict[str, float]] = {}
    
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
        key = f"{connection_id}:{action}"
        
        current_time = asyncio.get_event_loop().time()
        
        if key not in self._buckets:
            self._buckets[key] = {
                "tokens": float(limit),
                "last_update": current_time
            }
        
        bucket = self._buckets[key]
        
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
        keys_to_remove = [
            key for key in self._buckets 
            if key.startswith(f"{connection_id}:")
        ]
        for key in keys_to_remove:
            self._buckets.pop(key, None)


def require_ws_permission(permission: str):
    """
    Decorator for WebSocket message handlers that require permissions.
    
    Args:
        permission: Required permission string (e.g., "conversation.read")
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(
            connection: WebSocketConnection,
            message: Dict[str, Any],
            *args,
            **kwargs
        ):
            # Get connection metadata
            connection_manager = get_connection_manager()
            metadata = connection_manager.get_metadata(connection.id)
            
            if not metadata:
                await connection.websocket.send_json({
                    "type": "error",
                    "error": "connection_not_found",
                    "message": "Connection metadata not found"
                })
                return
            
            # Check permission
            async for db in get_async_session():
                permission_checker = PermissionChecker(db)
                has_permission = await permission_checker.check_permission(
                    user_id=metadata.user_id,
                    tenant_id=metadata.tenant_id,
                    permission=permission
                )
                
                if not has_permission:
                    await connection.websocket.send_json({
                        "type": "error",
                        "error": "insufficient_permissions",
                        "required": permission,
                        "message": f"Permission '{permission}' required"
                    })
                    logger.warning(
                        "WebSocket permission denied",
                        user_id=metadata.user_id,
                        permission=permission,
                        connection_id=connection.id
                    )
                    return
                
                # Call the wrapped function
                return await func(connection, message, *args, **kwargs)
                
        return wrapper
    return decorator


def require_ws_resource_permission(
    resource_type: str,
    resource_id_field: str = "resource_id",
    permission_suffix: str = "read"
):
    """
    Decorator for resource-specific permission checks.
    
    Args:
        resource_type: Type of resource (e.g., "conversation", "document")
        resource_id_field: Field in message containing resource ID
        permission_suffix: Permission action (e.g., "read", "write")
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(
            connection: WebSocketConnection,
            message: Dict[str, Any],
            *args,
            **kwargs
        ):
            # Get resource ID from message
            resource_id = message.get(resource_id_field)
            if not resource_id:
                await connection.websocket.send_json({
                    "type": "error",
                    "error": "missing_resource_id",
                    "message": f"Missing required field: {resource_id_field}"
                })
                return
            
            # Get connection metadata
            connection_manager = get_connection_manager()
            metadata = connection_manager.get_metadata(connection.id)
            
            if not metadata:
                await connection.websocket.send_json({
                    "type": "error",
                    "error": "connection_not_found",
                    "message": "Connection metadata not found"
                })
                return
            
            # Check resource permission
            async for db in get_async_session():
                permission_checker = PermissionChecker(db)
                has_permission = await permission_checker.check_resource_permission(
                    user_id=metadata.user_id,
                    tenant_id=metadata.tenant_id,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    permission=f"{resource_type}.{permission_suffix}"
                )
                
                if not has_permission:
                    await connection.websocket.send_json({
                        "type": "error",
                        "error": "resource_access_denied",
                        "resource_type": resource_type,
                        "resource_id": resource_id,
                        "message": f"Access denied to {resource_type}"
                    })
                    logger.warning(
                        "WebSocket resource access denied",
                        user_id=metadata.user_id,
                        resource_type=resource_type,
                        resource_id=resource_id,
                        connection_id=connection.id
                    )
                    return
                
                # Call the wrapped function
                return await func(connection, message, *args, **kwargs)
                
        return wrapper
    return decorator


def rate_limit(action: str):
    """
    Decorator for rate limiting WebSocket message handlers.
    
    Args:
        action: Action name for rate limiting
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(
            connection: WebSocketConnection,
            message: Dict[str, Any],
            *args,
            **kwargs
        ):
            # Get or create rate limiter
            if not hasattr(wrapper, '_rate_limiter'):
                wrapper._rate_limiter = WebSocketRateLimiter()
            
            # Check rate limit
            if not await wrapper._rate_limiter.check_rate_limit(
                connection.id, 
                action
            ):
                await connection.websocket.send_json({
                    "type": "error",
                    "error": "rate_limit_exceeded",
                    "action": action,
                    "message": "Too many requests. Please slow down."
                })
                logger.warning(
                    "WebSocket rate limit exceeded",
                    connection_id=connection.id,
                    action=action
                )
                return
            
            # Call the wrapped function
            return await func(connection, message, *args, **kwargs)
            
        return wrapper
    return decorator


async def handle_websocket_error(
    websocket: WebSocket,
    error: Exception,
    connection_id: Optional[str] = None
):
    """
    Handle WebSocket errors gracefully.
    
    Args:
        websocket: The WebSocket connection
        error: The exception that occurred
        connection_id: Optional connection identifier
    """
    error_message = {
        "type": "error",
        "error": "internal_error",
        "message": "An internal error occurred"
    }
    
    if isinstance(error, WebSocketDisconnect):
        # Client disconnected - no need to send error
        logger.info(
            "WebSocket client disconnected",
            connection_id=connection_id,
            code=error.code,
            reason=error.reason
        )
        return
    
    # Log the error
    logger.error(
        "WebSocket error",
        error=str(error),
        connection_id=connection_id,
        exc_info=True
    )
    
    # Try to send error message
    try:
        await websocket.send_json(error_message)
    except Exception:
        pass  # Connection might be closed
    
    # Close the connection
    try:
        await websocket.close(code=1011, reason="Internal error")
    except Exception:
        pass  # Connection might already be closed


class WebSocketMiddleware:
    """
    Middleware for WebSocket connections.
    Handles authentication, logging, and error handling.
    """
    
    def __init__(self, handler: Callable):
        self.handler = handler
        self.authenticator = get_websocket_authenticator()
        self.connection_manager = get_connection_manager()
    
    async def __call__(
        self,
        websocket: WebSocket,
        token: Optional[str] = None
    ):
        """
        Process WebSocket connection with middleware.
        
        Args:
            websocket: The WebSocket connection
            token: Optional JWT token from query params
        """
        connection = None
        
        try:
            # Authenticate connection
            auth_payload = await self.authenticator.authenticate_connection(
                websocket, 
                token
            )
            
            # Register connection
            connection = await self.connection_manager.connect(
                websocket=websocket,
                user_id=auth_payload.sub,
                tenant_id=auth_payload.tenant_id,
                session_id=auth_payload.session_id
            )
            
            # Call the actual handler
            await self.handler(connection)
            
        except WebSocketDisconnect as e:
            logger.info(
                "WebSocket disconnected during middleware",
                code=e.code,
                reason=e.reason
            )
        except Exception as e:
            await handle_websocket_error(
                websocket, 
                e, 
                connection.id if connection else None
            )
        finally:
            # Clean up
            if connection:
                await self.connection_manager.disconnect(connection.id)
                self.authenticator.remove_connection_auth(connection.id)


def websocket_middleware(handler: Callable) -> WebSocketMiddleware:
    """
    Create WebSocket middleware for a handler.
    
    Args:
        handler: The WebSocket handler function
        
    Returns:
        WebSocketMiddleware instance
    """
    return WebSocketMiddleware(handler)