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
from .token_refresh import get_token_refresh_handler

logger = get_logger(__name__)


# Note: Rate limiting and permission decorators have been moved to
# separate modules for better organization:
# - permissions.py: WebSocketRateLimiter, WebSocketPermissionManager
# - decorators.py: require_ws_permission, require_ws_resource_permission, rate_limit




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
        self.token_refresh_handler = get_token_refresh_handler()
    
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
            
            # Start token refresh timer
            await self.token_refresh_handler.start_refresh_timer(
                connection, auth_payload
            )
            
            try:
                # Call the actual handler
                await self.handler(connection)
            finally:
                # Stop refresh timer
                await self.token_refresh_handler.stop_refresh_timer(connection.id)
            
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