"""
Unit tests for WebSocket authentication.
Tests JWT validation, token refresh, and authentication flow.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta
from uuid import uuid4
import json

from fastapi import WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState
from jose import jwt, JWTError

from src.api.websocket.auth import WebSocketAuthenticator, TokenValidationError
from src.core.auth.jwt_manager import TokenPayload


class TestWebSocketAuthenticator:
    """Test WebSocket authentication functionality."""
    
    @pytest.fixture
    def authenticator(self):
        """Create WebSocketAuthenticator instance."""
        return WebSocketAuthenticator()
    
    @pytest.fixture
    def mock_websocket(self):
        """Create mock WebSocket."""
        ws = Mock(spec=WebSocket)
        ws.accept = AsyncMock()
        ws.send_json = AsyncMock()
        ws.receive_json = AsyncMock()
        ws.close = AsyncMock()
        ws.client_state = WebSocketState.CONNECTED
        ws.application_state = WebSocketState.CONNECTED
        return ws
    
    @pytest.fixture
    def valid_token_payload(self):
        """Create valid token payload."""
        return TokenPayload(
            sub=str(uuid4()),
            tenant_id=str(uuid4()),
            session_id=str(uuid4()),
            scopes=["read", "write"],
            iat=int(datetime.utcnow().timestamp()),
            exp=int((datetime.utcnow() + timedelta(minutes=30)).timestamp()),
            iss="test-issuer",
            aud="test-audience"
        )
    
    @pytest.mark.asyncio
    async def test_authenticate_with_token_param(
        self, 
        authenticator, 
        mock_websocket, 
        valid_token_payload
    ):
        """Test authentication with token in parameter."""
        # Mock JWT manager
        with patch.object(
            authenticator.jwt_manager, 
            'decode_access_token',
            return_value=valid_token_payload
        ):
            # Mock audit logging
            with patch('src.api.websocket.auth.get_async_session') as mock_get_session:
                mock_get_session.return_value = AsyncMock()
                mock_get_session.return_value.__aiter__.return_value = [Mock()]
                with patch('src.api.websocket.auth.AuthAuditService'):
                    # Authenticate
                    result = await authenticator.authenticate_connection(
                        mock_websocket,
                        token="valid-token",
                        device_id="test-device"
                    )
        
        # Verify result
        assert result == valid_token_payload
        
        # Verify auth success message sent
        mock_websocket.send_json.assert_called()
        call_args = mock_websocket.send_json.call_args[0][0]
        assert call_args["type"] == "auth_success"
        assert call_args["user_id"] == valid_token_payload.sub
        assert call_args["tenant_id"] == valid_token_payload.tenant_id
    
    @pytest.mark.asyncio
    async def test_authenticate_with_message(
        self, 
        authenticator, 
        mock_websocket, 
        valid_token_payload
    ):
        """Test authentication with token in first message."""
        # Mock receiving auth message
        mock_websocket.receive_json.return_value = {
            "type": "auth",
            "token": "valid-token",
            "device_id": "test-device"
        }
        
        # Mock JWT manager
        with patch.object(
            authenticator.jwt_manager, 
            'decode_access_token',
            return_value=valid_token_payload
        ):
            # Mock audit logging
            with patch('src.api.websocket.auth.get_async_session') as mock_get_session:
                mock_get_session.return_value = AsyncMock()
                mock_get_session.return_value.__aiter__.return_value = [Mock()]
                with patch('src.api.websocket.auth.AuthAuditService'):
                    # Authenticate without token param
                    result = await authenticator.authenticate_connection(
                        mock_websocket,
                        token=None
                    )
        
        # Verify WebSocket accepted
        mock_websocket.accept.assert_called_once()
        
        # Verify auth message received
        mock_websocket.receive_json.assert_called_once()
        
        # Verify result
        assert result == valid_token_payload
    
    @pytest.mark.asyncio
    async def test_authenticate_invalid_token(
        self, 
        authenticator, 
        mock_websocket
    ):
        """Test authentication with invalid token."""
        # Mock JWT error
        with patch.object(
            authenticator.jwt_manager, 
            'decode_access_token',
            side_effect=JWTError("Invalid token")
        ):
            # Mock audit logging
            with patch('src.api.websocket.auth.get_async_session') as mock_get_session:
                mock_get_session.return_value = AsyncMock()
                mock_get_session.return_value.__aiter__.return_value = [Mock()]
                with patch('src.api.websocket.auth.AuthAuditService'):
                    # Attempt authentication
                    with pytest.raises(WebSocketDisconnect) as exc_info:
                        await authenticator.authenticate_connection(
                            mock_websocket,
                            token="invalid-token"
                        )
        
        # Verify disconnect code
        assert exc_info.value.code == 1008
        assert "Invalid token" in exc_info.value.reason
        
        # Verify error sent before close
        error_calls = [
            call for call in mock_websocket.send_json.call_args_list
            if call[0][0].get("type") == "auth_error"
        ]
        assert len(error_calls) > 0
    
    @pytest.mark.asyncio
    async def test_authenticate_missing_token(
        self, 
        authenticator, 
        mock_websocket
    ):
        """Test authentication with missing token."""
        # Mock receiving auth message without token
        mock_websocket.receive_json.return_value = {
            "type": "auth"
            # Missing token field
        }
        
        # Mock audit logging
        with patch('src.api.websocket.auth.get_async_session') as mock_get_session:
            mock_get_session.return_value = AsyncMock()
            mock_get_session.return_value.__aiter__.return_value = [Mock()]
            with patch('src.api.websocket.auth.AuthAuditService'):
                # Attempt authentication
                with pytest.raises(WebSocketDisconnect) as exc_info:
                    await authenticator.authenticate_connection(
                        mock_websocket,
                        token=None
                    )
        
        # Verify disconnect
        assert exc_info.value.code == 1008
        assert "Authentication token required" in exc_info.value.reason
    
    @pytest.mark.asyncio
    async def test_authenticate_timeout(
        self, 
        authenticator, 
        mock_websocket
    ):
        """Test authentication timeout."""
        import asyncio
        
        # Mock timeout on receive
        mock_websocket.receive_json.side_effect = asyncio.TimeoutError()
        
        # Attempt authentication
        with pytest.raises(WebSocketDisconnect) as exc_info:
            await authenticator.authenticate_connection(
                mock_websocket,
                token=None
            )
        
        # Verify timeout disconnect
        assert exc_info.value.code == 1008
        assert "Authentication timeout" in exc_info.value.reason
    
    @pytest.mark.asyncio
    async def test_token_refresh_success(
        self, 
        authenticator, 
        mock_websocket, 
        valid_token_payload
    ):
        """Test successful token refresh."""
        connection_id = "test-connection"
        new_access_token = "new-access-token"
        new_refresh_token = "new-refresh-token"
        
        # Store initial auth
        authenticator._authenticated_connections[connection_id] = valid_token_payload
        
        # Mock token refresh
        with patch.object(
            authenticator.jwt_manager,
            'refresh_access_token',
            return_value=(new_access_token, new_refresh_token)
        ):
            with patch.object(
                authenticator.jwt_manager,
                'decode_access_token',
                return_value=valid_token_payload
            ):
                # Mock audit logging
                with patch('src.api.websocket.auth.get_async_session') as mock_get_session:
                    mock_get_session.return_value = AsyncMock()
                    mock_get_session.return_value.__aiter__.return_value = [Mock()]
                    with patch('src.api.websocket.auth.AuthAuditService'):
                        # Refresh token
                        result = await authenticator.validate_token_refresh(
                            mock_websocket,
                            "refresh-token",
                            connection_id
                        )
        
        # Verify new tokens sent
        mock_websocket.send_json.assert_called()
        refresh_msg = mock_websocket.send_json.call_args[0][0]
        assert refresh_msg["type"] == "token_refreshed"
        assert refresh_msg["access_token"] == new_access_token
        assert refresh_msg["refresh_token"] == new_refresh_token
        
        # Verify payload updated
        assert authenticator._authenticated_connections[connection_id] == valid_token_payload
    
    @pytest.mark.asyncio
    async def test_token_refresh_failure(
        self, 
        authenticator, 
        mock_websocket,
        valid_token_payload
    ):
        """Test failed token refresh."""
        connection_id = "test-connection"
        
        # Store initial auth
        authenticator._authenticated_connections[connection_id] = valid_token_payload
        
        # Mock refresh failure
        with patch.object(
            authenticator.jwt_manager,
            'refresh_access_token',
            side_effect=JWTError("Refresh token expired")
        ):
            # Mock audit logging
            with patch('src.api.websocket.auth.get_async_session') as mock_get_session:
                mock_get_session.return_value = AsyncMock()
                mock_get_session.return_value.__aiter__.return_value = [Mock()]
                with patch('src.api.websocket.auth.AuthAuditService'):
                    # Attempt refresh
                    with pytest.raises(TokenValidationError) as exc_info:
                        await authenticator.validate_token_refresh(
                            mock_websocket,
                            "expired-refresh-token",
                            connection_id
                        )
        
        # Verify error
        assert "Token refresh failed" in str(exc_info.value)
    
    def test_get_connection_auth(self, authenticator, valid_token_payload):
        """Test getting connection authentication data."""
        connection_id = "test-connection"
        
        # Store auth
        authenticator._authenticated_connections[connection_id] = valid_token_payload
        
        # Get auth
        result = authenticator.get_connection_auth(connection_id)
        assert result == valid_token_payload
        
        # Get non-existent
        result = authenticator.get_connection_auth("non-existent")
        assert result is None
    
    def test_remove_connection_auth(self, authenticator, valid_token_payload):
        """Test removing connection authentication data."""
        connection_id = "test-connection"
        
        # Store auth
        authenticator._authenticated_connections[connection_id] = valid_token_payload
        
        # Remove auth
        authenticator.remove_connection_auth(connection_id)
        assert connection_id not in authenticator._authenticated_connections
        
        # Remove non-existent (should not raise)
        authenticator.remove_connection_auth("non-existent")


class TestWebSocketAuthFlow:
    """Test complete WebSocket authentication flow."""
    
    @pytest.mark.asyncio
    async def test_full_auth_flow_query_param(self):
        """Test full authentication flow with query parameter."""
        from src.api.websocket.handlers import websocket_endpoint
        
        # Create mock WebSocket
        mock_ws = Mock(spec=WebSocket)
        mock_ws.accept = AsyncMock()
        mock_ws.send_json = AsyncMock()
        mock_ws.receive_json = AsyncMock()
        mock_ws.close = AsyncMock()
        mock_ws.client_state = WebSocketState.CONNECTED
        mock_ws.application_state = WebSocketState.CONNECTED
        
        # Create valid token
        valid_payload = {
            "sub": str(uuid4()),
            "tenant_id": str(uuid4()),
            "session_id": str(uuid4()),
            "scopes": ["read"],
            "iat": int(datetime.utcnow().timestamp()),
            "exp": int((datetime.utcnow() + timedelta(minutes=30)).timestamp()),
            "iss": "test",
            "aud": "test",
            "type": "access"
        }
        
        # Create TokenPayload first to ensure it has type field
        token_payload = TokenPayload(**valid_payload)
        
        # Mock JWT decoding
        with patch('src.api.websocket.auth.JWTManager.decode_access_token') as mock_decode:
            mock_decode.return_value = token_payload
            
            # Mock database and audit
            with patch('src.api.websocket.auth.get_async_session') as mock_auth_session:
                mock_auth_session.return_value = AsyncMock()
                mock_auth_session.return_value.__aiter__.return_value = [Mock()]
                with patch('src.api.websocket.auth.AuthAuditService'):
                    # Mock the enhanced connection manager and Redis
                    with patch('src.infrastructure.websocket.connection_manager.get_async_session') as mock_cm_session:
                        mock_cm_session.return_value = AsyncMock()
                        mock_cm_session.return_value.__aiter__.return_value = [Mock()]
                        with patch('src.infrastructure.websocket.connection_manager.AuthAuditService'):
                            # Mock Redis
                            with patch('src.infrastructure.websocket.connection_manager.get_redis_client') as mock_redis:
                                mock_redis_instance = AsyncMock()
                                mock_redis_instance.client = AsyncMock()
                                mock_redis.return_value = mock_redis_instance
                                
                                # Mock message loop to disconnect after welcome
                                mock_ws.receive_json.side_effect = WebSocketDisconnect(1000, "Normal")
                                
                                # Run endpoint
                                await websocket_endpoint(mock_ws, token="valid-token")
        
        # Verify WebSocket accepted (no explicit accept with token)
        # Verify auth success sent
        auth_success_calls = [
            call for call in mock_ws.send_json.call_args_list
            if call[0][0].get("type") == "auth_success"
        ]
        assert len(auth_success_calls) > 0
        
        # Verify welcome message sent
        welcome_calls = [
            call for call in mock_ws.send_json.call_args_list
            if call[0][0].get("type") == "connected"
        ]
        assert len(welcome_calls) > 0
    
    @pytest.mark.asyncio 
    async def test_full_auth_flow_message_based(self):
        """Test full authentication flow with message-based auth."""
        from src.api.websocket.handlers import websocket_endpoint
        
        # Create mock WebSocket
        mock_ws = Mock(spec=WebSocket)
        mock_ws.accept = AsyncMock()
        mock_ws.send_json = AsyncMock()
        mock_ws.receive_json = AsyncMock()
        mock_ws.close = AsyncMock()
        mock_ws.client_state = WebSocketState.CONNECTED
        mock_ws.application_state = WebSocketState.CONNECTED
        
        # Mock receiving auth message then disconnect
        auth_message = {
            "type": "auth",
            "token": "valid-token"
        }
        mock_ws.receive_json.side_effect = [
            auth_message,
            WebSocketDisconnect(1000, "Normal")
        ]
        
        # Create valid token payload
        valid_payload = {
            "sub": str(uuid4()),
            "tenant_id": str(uuid4()), 
            "session_id": str(uuid4()),
            "scopes": ["read"],
            "iat": int(datetime.utcnow().timestamp()),
            "exp": int((datetime.utcnow() + timedelta(minutes=30)).timestamp()),
            "iss": "test",
            "aud": "test",
            "type": "access"
        }
        
        # Create TokenPayload first to ensure it has type field
        token_payload = TokenPayload(**valid_payload)
        
        # Mock JWT decoding
        with patch('src.api.websocket.auth.JWTManager.decode_access_token') as mock_decode:
            mock_decode.return_value = token_payload
            
            # Mock database and audit
            with patch('src.api.websocket.auth.get_async_session') as mock_auth_session:
                mock_auth_session.return_value = AsyncMock()
                mock_auth_session.return_value.__aiter__.return_value = [Mock()]
                with patch('src.api.websocket.auth.AuthAuditService'):
                    # Mock the enhanced connection manager and Redis
                    with patch('src.infrastructure.websocket.connection_manager.get_async_session') as mock_cm_session:
                        mock_cm_session.return_value = AsyncMock()
                        mock_cm_session.return_value.__aiter__.return_value = [Mock()]
                        with patch('src.infrastructure.websocket.connection_manager.AuthAuditService'):
                            # Mock Redis
                            with patch('src.infrastructure.websocket.connection_manager.get_redis_client') as mock_redis:
                                mock_redis_instance = AsyncMock()
                                mock_redis_instance.client = AsyncMock()
                                mock_redis.return_value = mock_redis_instance
                                
                                # Run endpoint without token param
                                await websocket_endpoint(mock_ws, token=None)
        
        # Verify WebSocket accepted
        mock_ws.accept.assert_called_once()
        
        # Verify auth success sent
        auth_success_calls = [
            call for call in mock_ws.send_json.call_args_list
            if call[0][0].get("type") == "auth_success"
        ]
        assert len(auth_success_calls) > 0