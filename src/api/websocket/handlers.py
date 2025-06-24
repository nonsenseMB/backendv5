"""
WebSocket handlers and message routing.
Implements the main WebSocket endpoint and message handling logic.
"""

from typing import Dict, Any, Optional
from datetime import datetime
import asyncio

from fastapi import WebSocket, WebSocketDisconnect, Query

from ...core.logging import get_logger
from .auth import get_websocket_authenticator
from .connection_manager import get_connection_manager, WebSocketConnection
from .middleware import (
    websocket_middleware, 
    require_ws_permission, 
    require_ws_resource_permission,
    rate_limit,
    handle_websocket_error
)

logger = get_logger(__name__)


class WebSocketMessageHandler:
    """
    Handles different types of WebSocket messages.
    Routes messages to appropriate handlers based on message type.
    """
    
    def __init__(self):
        self.connection_manager = get_connection_manager()
        self.authenticator = get_websocket_authenticator()
        
        # Message type to handler mapping
        self.handlers = {
            "ping": self.handle_ping,
            "pong": self.handle_pong,
            "refresh_token": self.handle_token_refresh,
            "subscribe": self.handle_subscribe,
            "unsubscribe": self.handle_unsubscribe,
            "message": self.handle_message,
            "presence_update": self.handle_presence_update,
        }
    
    async def handle_message(
        self,
        connection: WebSocketConnection,
        message: Dict[str, Any]
    ):
        """
        Route message to appropriate handler based on type.
        
        Args:
            connection: The WebSocket connection
            message: The message to handle
        """
        message_type = message.get("type")
        
        if not message_type:
            await connection.websocket.send_json({
                "type": "error",
                "error": "missing_message_type",
                "message": "Message type is required"
            })
            return
        
        handler = self.handlers.get(message_type)
        
        if not handler:
            await connection.websocket.send_json({
                "type": "error",
                "error": "unknown_message_type",
                "message": f"Unknown message type: {message_type}"
            })
            return
        
        try:
            await handler(connection, message)
        except Exception as e:
            logger.error(
                "Error handling message",
                message_type=message_type,
                connection_id=connection.id,
                error=str(e),
                exc_info=True
            )
            await connection.websocket.send_json({
                "type": "error",
                "error": "message_handler_error",
                "message": "Failed to process message"
            })
    
    async def handle_ping(
        self,
        connection: WebSocketConnection,
        message: Dict[str, Any]
    ):
        """Handle ping message for connection keep-alive."""
        await connection.websocket.send_json({
            "type": "pong",
            "timestamp": datetime.utcnow().isoformat()
        })
        connection.update_activity()
    
    async def handle_pong(
        self,
        connection: WebSocketConnection,
        message: Dict[str, Any]
    ):
        """Handle pong response."""
        connection.update_activity()
    
    async def handle_token_refresh(
        self,
        connection: WebSocketConnection,
        message: Dict[str, Any]
    ):
        """Handle token refresh request."""
        refresh_token = message.get("refresh_token")
        
        if not refresh_token:
            await connection.websocket.send_json({
                "type": "error",
                "error": "missing_refresh_token",
                "message": "Refresh token is required"
            })
            return
        
        try:
            # Refresh the token
            new_payload = await self.authenticator.validate_token_refresh(
                connection.websocket,
                refresh_token,
                connection.id
            )
            
            # Update connection metadata
            metadata = self.connection_manager.get_metadata(connection.id)
            if metadata:
                # Update session ID if changed
                metadata.session_id = new_payload.session_id
            
            logger.info(
                "Token refreshed via WebSocket",
                connection_id=connection.id,
                user_id=new_payload.sub
            )
            
        except Exception as e:
            await connection.websocket.send_json({
                "type": "error",
                "error": "token_refresh_failed",
                "message": str(e)
            })
            # Close connection on refresh failure
            await connection.websocket.close(
                code=1008,
                reason="Token refresh failed"
            )
    
    @rate_limit("subscribe")
    @require_ws_permission("channel.subscribe")
    async def handle_subscribe(
        self,
        connection: WebSocketConnection,
        message: Dict[str, Any]
    ):
        """Handle channel subscription request."""
        channel = message.get("channel")
        
        if not channel:
            await connection.websocket.send_json({
                "type": "error",
                "error": "missing_channel",
                "message": "Channel is required"
            })
            return
        
        # Join the channel
        success = await self.connection_manager.join_channel(
            connection.id,
            channel
        )
        
        if success:
            await connection.websocket.send_json({
                "type": "subscribed",
                "channel": channel,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            logger.info(
                "WebSocket subscribed to channel",
                connection_id=connection.id,
                channel=channel
            )
        else:
            await connection.websocket.send_json({
                "type": "error",
                "error": "subscription_failed",
                "channel": channel,
                "message": "Failed to subscribe to channel"
            })
    
    @rate_limit("unsubscribe")
    async def handle_unsubscribe(
        self,
        connection: WebSocketConnection,
        message: Dict[str, Any]
    ):
        """Handle channel unsubscribe request."""
        channel = message.get("channel")
        
        if not channel:
            await connection.websocket.send_json({
                "type": "error",
                "error": "missing_channel",
                "message": "Channel is required"
            })
            return
        
        # Leave the channel
        await self.connection_manager.leave_channel(
            connection.id,
            channel
        )
        
        await connection.websocket.send_json({
            "type": "unsubscribed",
            "channel": channel,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        logger.info(
            "WebSocket unsubscribed from channel",
            connection_id=connection.id,
            channel=channel
        )
    
    @rate_limit("message.create")
    @require_ws_resource_permission("conversation", "conversation_id", "write")
    async def handle_message(
        self,
        connection: WebSocketConnection,
        message: Dict[str, Any]
    ):
        """
        Handle sending a message to a conversation.
        This is a placeholder - implement based on your messaging system.
        """
        conversation_id = message.get("conversation_id")
        content = message.get("content")
        
        if not conversation_id or not content:
            await connection.websocket.send_json({
                "type": "error",
                "error": "missing_fields",
                "message": "conversation_id and content are required"
            })
            return
        
        # Create message (placeholder)
        message_id = str(asyncio.get_event_loop().time())
        
        # Broadcast to conversation channel
        await self.connection_manager.send_to_channel(
            f"conversation:{conversation_id}",
            {
                "type": "new_message",
                "message_id": message_id,
                "conversation_id": conversation_id,
                "user_id": connection.user_id,
                "content": content,
                "timestamp": datetime.utcnow().isoformat()
            },
            exclude_connection=connection.id
        )
        
        # Send confirmation to sender
        await connection.websocket.send_json({
            "type": "message_sent",
            "message_id": message_id,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    @rate_limit("presence.update")
    async def handle_presence_update(
        self,
        connection: WebSocketConnection,
        message: Dict[str, Any]
    ):
        """Handle presence/status update."""
        status = message.get("status", "online")
        
        # Validate status
        valid_statuses = ["online", "away", "busy", "offline"]
        if status not in valid_statuses:
            await connection.websocket.send_json({
                "type": "error",
                "error": "invalid_status",
                "message": f"Status must be one of: {valid_statuses}"
            })
            return
        
        # Broadcast presence update to tenant
        await self.connection_manager.broadcast_to_tenant(
            connection.tenant_id,
            {
                "type": "presence_update",
                "user_id": connection.user_id,
                "status": status,
                "timestamp": datetime.utcnow().isoformat()
            },
            exclude_connection=connection.id
        )
        
        # Send confirmation
        await connection.websocket.send_json({
            "type": "presence_updated",
            "status": status,
            "timestamp": datetime.utcnow().isoformat()
        })


async def websocket_handler(connection: WebSocketConnection):
    """
    Main WebSocket connection handler.
    Processes messages and maintains connection.
    
    Args:
        connection: The authenticated WebSocket connection
    """
    message_handler = WebSocketMessageHandler()
    
    try:
        # Send welcome message
        await connection.websocket.send_json({
            "type": "connected",
            "connection_id": connection.id,
            "user_id": connection.user_id,
            "tenant_id": connection.tenant_id,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        # Start heartbeat task
        heartbeat_task = asyncio.create_task(
            heartbeat_loop(connection)
        )
        
        # Message processing loop
        while True:
            try:
                # Receive message
                message = await connection.websocket.receive_json()
                
                # Update activity
                connection.update_activity()
                
                # Handle message
                await message_handler.handle_message(connection, message)
                
            except WebSocketDisconnect:
                logger.info(
                    "WebSocket disconnected",
                    connection_id=connection.id
                )
                break
            except Exception as e:
                logger.error(
                    "Error processing WebSocket message",
                    connection_id=connection.id,
                    error=str(e),
                    exc_info=True
                )
                await connection.websocket.send_json({
                    "type": "error",
                    "error": "processing_error",
                    "message": "Failed to process message"
                })
    
    finally:
        # Cancel heartbeat
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass


async def heartbeat_loop(connection: WebSocketConnection, interval: int = 30):
    """
    Send periodic heartbeat to keep connection alive.
    
    Args:
        connection: The WebSocket connection
        interval: Heartbeat interval in seconds
    """
    try:
        while connection.is_connected:
            await asyncio.sleep(interval)
            
            # Send ping
            await connection.websocket.send_json({
                "type": "ping",
                "timestamp": datetime.utcnow().isoformat()
            })
            
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.error(
            "Heartbeat error",
            connection_id=connection.id,
            error=str(e)
        )


# Main WebSocket endpoint
async def websocket_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(None, description="JWT access token")
):
    """
    Main WebSocket endpoint with JWT authentication.
    
    Args:
        websocket: The WebSocket connection
        token: Optional JWT token from query parameters
    """
    # Apply middleware and handle connection
    middleware = websocket_middleware(websocket_handler)
    await middleware(websocket, token)