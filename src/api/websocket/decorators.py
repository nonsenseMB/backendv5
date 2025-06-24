"""
WebSocket decorators for permissions and rate limiting.
Provides convenient decorators for WebSocket message handlers.
"""

from typing import Callable, Dict, Any, Optional
from functools import wraps

from ...core.logging import get_logger
from .connection_manager import get_connection_manager, WebSocketConnection
from .permissions import get_permission_manager, get_rate_limiter

logger = get_logger(__name__)


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
            permission_manager = get_permission_manager()
            has_permission = await permission_manager.check_permission(
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
            permission_manager = get_permission_manager()
            permission = f"{resource_type}.{permission_suffix}"
            
            has_permission = await permission_manager.check_resource_permission(
                user_id=metadata.user_id,
                tenant_id=metadata.tenant_id,
                resource_type=resource_type,
                resource_id=resource_id,
                permission=permission
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
            # Get rate limiter
            rate_limiter = get_rate_limiter()
            
            # Check rate limit
            if not await rate_limiter.check_rate_limit(connection.id, action):
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


def combine_decorators(*decorators):
    """
    Combine multiple decorators into one.
    
    Args:
        *decorators: Decorators to combine
        
    Example:
        @combine_decorators(
            rate_limit("message.create"),
            require_ws_permission("message.write")
        )
        async def handle_message(connection, message):
            pass
    """
    def decorator(func):
        for dec in reversed(decorators):
            func = dec(func)
        return func
    return decorator


def ws_handler_error_handling(func: Callable):
    """
    Decorator to add error handling to WebSocket handlers.
    Catches exceptions and sends appropriate error messages.
    """
    @wraps(func)
    async def wrapper(
        connection: WebSocketConnection,
        message: Dict[str, Any],
        *args,
        **kwargs
    ):
        try:
            return await func(connection, message, *args, **kwargs)
        except Exception as e:
            logger.error(
                "WebSocket handler error",
                handler=func.__name__,
                error=str(e),
                connection_id=connection.id,
                exc_info=True
            )
            
            # Send error message to client
            try:
                await connection.websocket.send_json({
                    "type": "error",
                    "error": "handler_error",
                    "message": "An error occurred processing your request"
                })
            except Exception as send_error:
                logger.debug(
                    "Failed to send error message to client",
                    error=str(send_error),
                    connection_id=connection.id
                )
                
    return wrapper


def require_ws_authentication(func: Callable):
    """
    Decorator to ensure WebSocket connection is authenticated.
    This is typically already handled by the connection manager,
    but can be used as an extra check.
    """
    @wraps(func)
    async def wrapper(
        connection: WebSocketConnection,
        *args,
        **kwargs
    ):
        # Verify connection has valid user/tenant
        if not connection.user_id or not connection.tenant_id:
            await connection.websocket.send_json({
                "type": "error",
                "error": "authentication_required",
                "message": "Authentication required for this operation"
            })
            return
        
        return await func(connection, *args, **kwargs)
        
    return wrapper