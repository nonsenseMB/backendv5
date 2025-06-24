"""
WebSocket token refresh mechanism.
Handles automatic token refresh reminders and token renewal for long-lived connections.
"""

from typing import Optional, Dict, Any, Set
from datetime import datetime, timedelta
import asyncio
import logging
from uuid import UUID

from fastapi import WebSocket
from starlette.websockets import WebSocketState

from ...core.auth.jwt_manager import JWTManager, TokenPayload
from ...core.logging import get_logger
from ...infrastructure.websocket.connection_manager import WebSocketConnection
from .connection_manager import ConnectionManager, get_connection_manager
from .auth import get_websocket_authenticator

logger = get_logger(__name__)


class TokenRefreshHandler:
    """
    Manages token refresh for WebSocket connections.
    Sends periodic reminders and handles token renewal.
    """
    
    def __init__(
        self,
        connection_manager: Optional[ConnectionManager] = None,
        refresh_interval: int = 300,  # 5 minutes
        warning_threshold: int = 60    # 1 minute before expiry
    ):
        self.connection_manager = connection_manager or get_connection_manager()
        self.refresh_interval = refresh_interval
        self.warning_threshold = warning_threshold
        self.jwt_manager = JWTManager()
        self._refresh_tasks: Dict[str, asyncio.Task] = {}
        self._authenticator = get_websocket_authenticator()
    
    async def start_refresh_timer(
        self,
        connection: WebSocketConnection,
        token_payload: TokenPayload
    ):
        """
        Start periodic token refresh reminders for a connection.
        
        Args:
            connection: WebSocket connection
            token_payload: Current token payload with expiration
        """
        connection_id = connection.id
        
        # Cancel any existing timer for this connection
        if connection_id in self._refresh_tasks:
            self._refresh_tasks[connection_id].cancel()
        
        # Create new refresh task
        task = asyncio.create_task(
            self._refresh_timer_loop(connection, token_payload)
        )
        self._refresh_tasks[connection_id] = task
        
        logger.info(
            "Started token refresh timer",
            connection_id=connection_id,
            user_id=token_payload.sub,
            refresh_interval=self.refresh_interval
        )
    
    async def stop_refresh_timer(self, connection_id: str):
        """
        Stop refresh timer for a connection.
        
        Args:
            connection_id: Connection identifier
        """
        if connection_id in self._refresh_tasks:
            self._refresh_tasks[connection_id].cancel()
            del self._refresh_tasks[connection_id]
            
            logger.debug(
                "Stopped token refresh timer",
                connection_id=connection_id
            )
    
    async def _refresh_timer_loop(
        self,
        connection: WebSocketConnection,
        initial_payload: TokenPayload
    ):
        """
        Timer loop that sends refresh reminders.
        
        Args:
            connection: WebSocket connection
            initial_payload: Initial token payload
        """
        try:
            current_payload = initial_payload
            
            while connection.is_connected:
                # Calculate time until token expiry
                now = datetime.utcnow()
                
                # Get expiry time from payload
                if current_payload.exp:
                    expiry_time = datetime.fromtimestamp(current_payload.exp)
                    time_until_expiry = (expiry_time - now).total_seconds()
                else:
                    # No expiry, wait for refresh interval
                    time_until_expiry = self.refresh_interval
                
                # Wait until we need to send reminder
                if time_until_expiry > self.warning_threshold:
                    wait_time = min(
                        self.refresh_interval,
                        time_until_expiry - self.warning_threshold
                    )
                    await asyncio.sleep(wait_time)
                else:
                    # Token about to expire, send immediate reminder
                    await self._send_refresh_reminder(
                        connection,
                        int(max(0, time_until_expiry))
                    )
                    
                    # Wait for refresh or until expiry
                    await asyncio.sleep(max(1, time_until_expiry))
                    
                    # Check if token was refreshed
                    auth_data = self._authenticator.get_connection_auth(connection.id)
                    if auth_data and auth_data.exp != current_payload.exp:
                        current_payload = auth_data
                        logger.info(
                            "Token refreshed",
                            connection_id=connection.id,
                            user_id=current_payload.sub
                        )
                    else:
                        # Token expired without refresh
                        logger.warning(
                            "Token expired without refresh",
                            connection_id=connection.id,
                            user_id=current_payload.sub
                        )
                        
                        await self._handle_token_expired(connection)
                        break
                
                # Send periodic reminder if still connected
                if connection.is_connected:
                    auth_data = self._authenticator.get_connection_auth(connection.id)
                    if auth_data:
                        current_payload = auth_data
                        
                        # Calculate current time to expiry
                        now = datetime.utcnow()
                        if current_payload.exp:
                            expiry_time = datetime.fromtimestamp(current_payload.exp)
                            time_until_expiry = (expiry_time - now).total_seconds()
                            
                            if time_until_expiry <= self.warning_threshold:
                                await self._send_refresh_reminder(
                                    connection,
                                    int(max(0, time_until_expiry))
                                )
                
        except asyncio.CancelledError:
            logger.debug(
                "Refresh timer cancelled",
                connection_id=connection.id
            )
        except Exception as e:
            logger.error(
                "Error in refresh timer",
                error=str(e),
                connection_id=connection.id,
                exc_info=True
            )
    
    async def _send_refresh_reminder(
        self,
        connection: WebSocketConnection,
        expires_in: int
    ):
        """
        Send token refresh reminder to client.
        
        Args:
            connection: WebSocket connection
            expires_in: Seconds until token expires
        """
        try:
            message = {
                "type": "token_refresh_required",
                "expires_in": expires_in,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            await self.connection_manager.send_to_connection(
                connection.id,
                message
            )
            
            logger.debug(
                "Sent refresh reminder",
                connection_id=connection.id,
                expires_in=expires_in
            )
            
        except Exception as e:
            logger.error(
                "Failed to send refresh reminder",
                error=str(e),
                connection_id=connection.id
            )
    
    async def handle_token_refresh(
        self,
        connection: WebSocketConnection,
        refresh_token: str
    ) -> bool:
        """
        Handle token refresh request from client.
        
        Args:
            connection: WebSocket connection
            refresh_token: JWT refresh token
            
        Returns:
            True if refresh successful, False otherwise
        """
        try:
            # Get current auth data
            current_auth = self._authenticator.get_connection_auth(connection.id)
            if not current_auth:
                logger.error(
                    "No auth data for connection",
                    connection_id=connection.id
                )
                return False
            
            # Refresh tokens
            new_access_token, new_refresh_token = self.jwt_manager.refresh_access_token(
                refresh_token
            )
            
            # Decode new access token
            new_payload = self.jwt_manager.decode_access_token(new_access_token)
            
            # Verify user hasn't changed
            if new_payload.sub != current_auth.sub:
                logger.error(
                    "User mismatch in refresh",
                    connection_id=connection.id,
                    old_user=current_auth.sub,
                    new_user=new_payload.sub
                )
                return False
            
            # Update connection auth
            await self._update_connection_auth(connection, new_payload)
            
            # Send new tokens to client
            response = {
                "type": "token_refreshed",
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
                "expires_in": self.jwt_manager.access_token_expire_minutes * 60,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            await self.connection_manager.send_to_connection(
                connection.id,
                response
            )
            
            logger.info(
                "Token refresh successful",
                connection_id=connection.id,
                user_id=new_payload.sub
            )
            
            # Restart refresh timer with new token
            await self.start_refresh_timer(connection, new_payload)
            
            return True
            
        except Exception as e:
            logger.error(
                "Token refresh failed",
                error=str(e),
                connection_id=connection.id,
                exc_info=True
            )
            
            # Send error to client
            try:
                error_response = {
                    "type": "token_refresh_failed",
                    "error": "Failed to refresh token",
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                await self.connection_manager.send_to_connection(
                    connection.id,
                    error_response
                )
            except Exception as send_error:
                logger.debug(
                    "Failed to send token refresh error response",
                    error=str(send_error),
                    connection_id=connection.id
                )
            
            return False
    
    async def _update_connection_auth(
        self,
        connection: WebSocketConnection,
        new_payload: TokenPayload
    ):
        """
        Update connection authentication data.
        
        Args:
            connection: WebSocket connection
            new_payload: New token payload
        """
        # Update in authenticator
        self._authenticator._authenticated_connections[connection.id] = new_payload
        
        # Update connection metadata if needed
        metadata = self.connection_manager.get_metadata(connection.id)
        if metadata:
            # Refresh permissions if needed
            if hasattr(new_payload, 'scopes') and new_payload.scopes:
                metadata.update_permissions(set(new_payload.scopes))
        
        logger.debug(
            "Updated connection auth",
            connection_id=connection.id,
            user_id=new_payload.sub
        )
    
    async def _handle_token_expired(self, connection: WebSocketConnection):
        """
        Handle token expiration.
        
        Args:
            connection: WebSocket connection
        """
        try:
            # Send expiration notice
            message = {
                "type": "token_expired",
                "message": "Authentication token expired",
                "timestamp": datetime.utcnow().isoformat()
            }
            
            await self.connection_manager.send_to_connection(
                connection.id,
                message
            )
            
            # Give client a chance to read the message
            await asyncio.sleep(1)
            
            # Disconnect
            await self.connection_manager.disconnect(
                connection.id,
                close_code=1008,
                reason="Token expired"
            )
            
        except Exception as e:
            logger.error(
                "Error handling token expiration",
                error=str(e),
                connection_id=connection.id
            )
    
    def get_active_timers(self) -> Set[str]:
        """Get set of connection IDs with active refresh timers."""
        return set(self._refresh_tasks.keys())
    
    async def shutdown(self):
        """Shutdown all refresh timers."""
        # Cancel all tasks
        for task in self._refresh_tasks.values():
            task.cancel()
        
        # Wait for cancellation
        if self._refresh_tasks:
            await asyncio.gather(
                *self._refresh_tasks.values(),
                return_exceptions=True
            )
        
        self._refresh_tasks.clear()
        
        logger.info("Token refresh handler shutdown")


# Global instance
_token_refresh_handler: Optional[TokenRefreshHandler] = None


def get_token_refresh_handler() -> TokenRefreshHandler:
    """Get singleton token refresh handler."""
    global _token_refresh_handler
    if _token_refresh_handler is None:
        _token_refresh_handler = TokenRefreshHandler()
    return _token_refresh_handler