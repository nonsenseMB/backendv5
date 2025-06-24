"""
WebSocket authentication module.
Handles JWT validation and authentication for WebSocket connections.
"""

from typing import Optional, Dict, Any
from uuid import UUID
from datetime import datetime

from fastapi import WebSocket, WebSocketDisconnect
from jose import JWTError

from ...core.auth.jwt_manager import JWTManager, TokenPayload
from ...core.logging import get_logger
from ...core.logging.auth_audit import AuthAuditService, AuthAuditEvent, AuditSeverity
from ...infrastructure.database.session import get_async_session
# Token validation error
class TokenValidationError(Exception):
    """Raised when token validation fails."""
    pass

logger = get_logger(__name__)


class WebSocketAuthenticator:
    """
    Handles WebSocket authentication using JWT tokens.
    Supports both query parameter and message-based authentication.
    """
    
    def __init__(self):
        self.jwt_manager = JWTManager()
        self._authenticated_connections: Dict[str, TokenPayload] = {}
    
    async def authenticate_connection(
        self,
        websocket: WebSocket,
        token: Optional[str] = None,
        device_id: Optional[str] = None
    ) -> TokenPayload:
        """
        Authenticate a WebSocket connection using JWT token.
        
        Args:
            websocket: The WebSocket connection
            token: JWT access token (optional if provided in first message)
            device_id: Optional device ID for device binding
            
        Returns:
            TokenPayload with user information
            
        Raises:
            WebSocketDisconnect: If authentication fails
        """
        try:
            # If no token provided, wait for auth message
            if not token:
                await websocket.accept()
                
                try:
                    # Set timeout for auth message
                    auth_timeout = 30  # seconds - configurable via environment
                    auth_msg = await self._wait_for_auth_message(websocket, auth_timeout)
                    token = auth_msg.get("token")
                    device_id = auth_msg.get("device_id", device_id)
                    
                except TimeoutError:
                    await self._close_with_error(
                        websocket, 
                        code=1008, 
                        reason="Authentication timeout"
                    )
                    raise WebSocketDisconnect(code=1008, reason="Authentication timeout")
                    
                except Exception as e:
                    await self._close_with_error(
                        websocket,
                        code=1008,
                        reason="Invalid authentication message"
                    )
                    raise WebSocketDisconnect(code=1008, reason="Invalid authentication message")
            
            if not token:
                await self._close_with_error(
                    websocket,
                    code=1008,
                    reason="Authentication token required"
                )
                raise WebSocketDisconnect(code=1008, reason="Authentication token required")
            
            # Validate JWT token
            try:
                payload = self.jwt_manager.decode_access_token(token)
                
                # Log successful authentication
                await self._log_auth_event(
                    AuthAuditEvent.LOGIN_SUCCESS,
                    user_id=UUID(payload.sub),
                    tenant_id=UUID(payload.tenant_id),
                    session_id=UUID(payload.session_id),
                    device_id=device_id,
                    success=True
                )
                
                # Store authenticated payload
                connection_id = str(id(websocket))
                self._authenticated_connections[connection_id] = payload
                
                # Send authentication success response
                await websocket.send_json({
                    "type": "auth_success",
                    "user_id": payload.sub,
                    "tenant_id": payload.tenant_id,
                    "session_id": payload.session_id,
                    "timestamp": datetime.utcnow().isoformat()
                })
                
                logger.info(
                    "WebSocket authenticated",
                    user_id=payload.sub,
                    tenant_id=payload.tenant_id,
                    session_id=payload.session_id,
                    device_id=device_id
                )
                
                return payload
                
            except JWTError as e:
                # Log failed authentication
                await self._log_auth_event(
                    AuthAuditEvent.LOGIN_FAILED,
                    device_id=device_id,
                    success=False,
                    error_message=str(e)
                )
                
                await self._close_with_error(
                    websocket,
                    code=1008,
                    reason=f"Invalid token: {str(e)}"
                )
                raise WebSocketDisconnect(code=1008, reason=f"Invalid token: {str(e)}")
                
        except WebSocketDisconnect:
            raise
        except Exception as e:
            logger.error(
                "WebSocket authentication error",
                error=str(e),
                exc_info=True
            )
            await self._close_with_error(
                websocket,
                code=1011,
                reason="Internal authentication error"
            )
            raise WebSocketDisconnect(code=1011, reason="Internal authentication error")
    
    async def validate_token_refresh(
        self,
        websocket: WebSocket,
        refresh_token: str,
        connection_id: str
    ) -> TokenPayload:
        """
        Validate and refresh access token for existing connection.
        
        Args:
            websocket: The WebSocket connection
            refresh_token: JWT refresh token
            connection_id: Connection identifier
            
        Returns:
            New TokenPayload with refreshed information
            
        Raises:
            TokenValidationError: If refresh fails
        """
        try:
            # Refresh tokens
            new_access_token, new_refresh_token = self.jwt_manager.refresh_access_token(
                refresh_token
            )
            
            # Decode new access token to get payload
            new_payload = self.jwt_manager.decode_access_token(new_access_token)
            
            # Update stored payload
            self._authenticated_connections[connection_id] = new_payload
            
            # Send new tokens to client
            await websocket.send_json({
                "type": "token_refreshed",
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
                "expires_in": self.jwt_manager.access_token_expire_minutes * 60,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            # Log token refresh
            await self._log_auth_event(
                AuthAuditEvent.TOKEN_REFRESHED,
                user_id=UUID(new_payload.sub),
                tenant_id=UUID(new_payload.tenant_id),
                session_id=UUID(new_payload.session_id),
                success=True
            )
            
            logger.info(
                "WebSocket token refreshed",
                user_id=new_payload.sub,
                connection_id=connection_id
            )
            
            return new_payload
            
        except Exception as e:
            logger.error(
                "Token refresh failed",
                error=str(e),
                connection_id=connection_id
            )
            
            # Log failed refresh
            if connection_id in self._authenticated_connections:
                old_payload = self._authenticated_connections[connection_id]
                await self._log_auth_event(
                    AuthAuditEvent.TOKEN_REFRESHED,
                    user_id=UUID(old_payload.sub),
                    tenant_id=UUID(old_payload.tenant_id),
                    session_id=UUID(old_payload.session_id),
                    success=False,
                    error_message=str(e)
                )
            
            raise TokenValidationError(f"Token refresh failed: {str(e)}")
    
    def get_connection_auth(self, connection_id: str) -> Optional[TokenPayload]:
        """Get authentication payload for a connection."""
        return self._authenticated_connections.get(connection_id)
    
    def remove_connection_auth(self, connection_id: str):
        """Remove authentication data when connection closes."""
        self._authenticated_connections.pop(connection_id, None)
    
    async def _wait_for_auth_message(
        self, 
        websocket: WebSocket, 
        timeout: int
    ) -> Dict[str, Any]:
        """
        Wait for authentication message from client.
        
        Args:
            websocket: The WebSocket connection
            timeout: Timeout in seconds
            
        Returns:
            Authentication message data
            
        Raises:
            TimeoutError: If no message received within timeout
            ValueError: If message is not valid JSON or not auth type
        """
        import asyncio
        
        try:
            # Wait for message with timeout
            message = await asyncio.wait_for(
                websocket.receive_json(),
                timeout=timeout
            )
            
            # Validate message structure
            if not isinstance(message, dict):
                raise ValueError("Invalid message format")
            
            if message.get("type") != "auth":
                raise ValueError("Expected auth message")
            
            return message
            
        except asyncio.TimeoutError:
            raise TimeoutError("Authentication timeout")
        except Exception as e:
            logger.warning(
                "Invalid auth message received",
                error=str(e)
            )
            raise
    
    async def _close_with_error(
        self,
        websocket: WebSocket,
        code: int,
        reason: str
    ):
        """Close WebSocket connection with error."""
        try:
            # Try to send error message before closing
            await websocket.send_json({
                "type": "auth_error",
                "error": reason,
                "code": code,
                "timestamp": datetime.utcnow().isoformat()
            })
        except Exception:
            pass  # Connection might already be closed
        
        try:
            await websocket.close(code=code, reason=reason)
        except Exception:
            pass  # Connection might already be closed
    
    async def _log_auth_event(
        self,
        event_type: AuthAuditEvent,
        user_id: Optional[UUID] = None,
        tenant_id: Optional[UUID] = None,
        session_id: Optional[UUID] = None,
        device_id: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None
    ):
        """Log authentication event to audit system."""
        try:
            # Get database session
            async for db in get_async_session():
                audit_service = AuthAuditService(db)
                
                await audit_service.log_auth_event(
                    event_type=event_type,
                    user_id=user_id,
                    tenant_id=tenant_id,
                    session_id=session_id,
                    action="websocket_auth",
                    details={
                        "connection_type": "websocket",
                        "device_id": device_id
                    },
                    severity=AuditSeverity.INFO if success else AuditSeverity.WARNING,
                    success=success,
                    error_message=error_message
                )
                break
            
        except Exception as e:
            logger.error(
                "Failed to log auth event",
                error=str(e),
                event_type=event_type.value
            )


# Global authenticator instance
_websocket_authenticator: Optional[WebSocketAuthenticator] = None


def get_websocket_authenticator() -> WebSocketAuthenticator:
    """Get singleton WebSocket authenticator instance."""
    global _websocket_authenticator
    if _websocket_authenticator is None:
        _websocket_authenticator = WebSocketAuthenticator()
    return _websocket_authenticator