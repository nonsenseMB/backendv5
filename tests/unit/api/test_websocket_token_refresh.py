"""
Unit tests for WebSocket token refresh mechanism.
Tests refresh timers, token renewal, and error handling.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta
from uuid import uuid4
import asyncio
import json

from fastapi import WebSocket
from starlette.websockets import WebSocketState

from src.api.websocket.token_refresh import TokenRefreshHandler, get_token_refresh_handler
from src.infrastructure.websocket.connection_manager import WebSocketConnection
from src.core.auth.jwt_manager import TokenPayload


class TestTokenRefreshHandler:
    """Test token refresh handler functionality."""
    
    @pytest.fixture
    def handler(self):
        """Create token refresh handler instance."""
        return TokenRefreshHandler(
            refresh_interval=5,  # 5 seconds for testing
            warning_threshold=2   # 2 seconds for testing
        )
    
    @pytest.fixture
    def mock_connection(self):
        """Create mock WebSocket connection."""
        ws = Mock(spec=WebSocket)
        ws.send_json = AsyncMock()
        ws.close = AsyncMock()
        ws.client_state = WebSocketState.CONNECTED
        ws.application_state = WebSocketState.CONNECTED
        
        connection = WebSocketConnection(
            id="test-conn-123",
            websocket=ws,
            user_id=str(uuid4()),
            tenant_id=str(uuid4()),
            session_id=str(uuid4())
        )
        return connection
    
    @pytest.fixture
    def token_payload(self):
        """Create token payload with expiration."""
        return TokenPayload(
            sub=str(uuid4()),
            tenant_id=str(uuid4()),
            session_id=str(uuid4()),
            scopes=["read", "write"],
            iat=int(datetime.utcnow().timestamp()),
            exp=int((datetime.utcnow() + timedelta(minutes=5)).timestamp()),
            iss="test-issuer",
            aud="test-audience"
        )
    
    @pytest.mark.asyncio
    async def test_start_refresh_timer(self, handler, mock_connection, token_payload):
        """Test starting refresh timer."""
        # Start timer
        await handler.start_refresh_timer(mock_connection, token_payload)
        
        # Verify timer started
        assert mock_connection.id in handler._refresh_tasks
        assert handler._refresh_tasks[mock_connection.id] is not None
        
        # Stop timer for cleanup
        await handler.stop_refresh_timer(mock_connection.id)
    
    @pytest.mark.asyncio
    async def test_stop_refresh_timer(self, handler, mock_connection, token_payload):
        """Test stopping refresh timer."""
        # Start timer
        await handler.start_refresh_timer(mock_connection, token_payload)
        assert mock_connection.id in handler._refresh_tasks
        
        # Stop timer
        await handler.stop_refresh_timer(mock_connection.id)
        
        # Verify timer stopped
        assert mock_connection.id not in handler._refresh_tasks
    
    @pytest.mark.asyncio
    async def test_refresh_reminder_sent(self, handler, mock_connection, token_payload):
        """Test that refresh reminders are sent."""
        # Create token expiring soon
        token_payload.exp = int((datetime.utcnow() + timedelta(seconds=3)).timestamp())
        
        # Mock authenticator and connection manager
        with patch.object(handler._authenticator, 'get_connection_auth', return_value=token_payload):
            with patch.object(handler.connection_manager, 'send_to_connection') as mock_send:
                # Start timer
                await handler.start_refresh_timer(mock_connection, token_payload)
                
                # Wait for reminder (should be sent immediately due to low expiry time)
                await asyncio.sleep(0.5)
                
                # Verify reminder sent
                mock_send.assert_called()
                calls = [call for call in mock_send.call_args_list
                        if call[0][1].get("type") == "token_refresh_required"]
                assert len(calls) > 0
                
                reminder = calls[0][0][1]
                assert reminder["type"] == "token_refresh_required"
                assert "expires_in" in reminder
                assert reminder["expires_in"] <= 3
        
        # Cleanup
        await handler.stop_refresh_timer(mock_connection.id)
    
    @pytest.mark.asyncio
    async def test_handle_token_refresh_success(self, handler, mock_connection):
        """Test successful token refresh."""
        refresh_token = "valid-refresh-token"
        new_access_token = "new-access-token"
        new_refresh_token = "new-refresh-token"
        
        # Create new payload
        new_payload = TokenPayload(
            sub=mock_connection.user_id,
            tenant_id=mock_connection.tenant_id,
            session_id=mock_connection.session_id,
            scopes=["read", "write"],
            iat=int(datetime.utcnow().timestamp()),
            exp=int((datetime.utcnow() + timedelta(minutes=30)).timestamp()),
            iss="test-issuer",
            aud="test-audience"
        )
        
        # Mock current auth
        with patch.object(
            handler._authenticator,
            'get_connection_auth',
            return_value=new_payload
        ):
            # Mock JWT manager
            with patch.object(
                handler.jwt_manager,
                'refresh_access_token',
                return_value=(new_access_token, new_refresh_token)
            ):
                with patch.object(
                    handler.jwt_manager,
                    'decode_access_token',
                    return_value=new_payload
                ):
                    # Mock connection manager
                    with patch.object(
                        handler.connection_manager,
                        'send_to_connection',
                        return_value=True
                    ) as mock_send:
                        # Refresh token
                        result = await handler.handle_token_refresh(
                            mock_connection,
                            refresh_token
                        )
        
        # Verify success
        assert result is True
        
        # Verify response sent
        mock_send.assert_called()
        response = mock_send.call_args[0][1]
        assert response["type"] == "token_refreshed"
        assert response["access_token"] == new_access_token
        assert response["refresh_token"] == new_refresh_token
        assert response["expires_in"] == handler.jwt_manager.access_token_expire_minutes * 60
    
    @pytest.mark.asyncio
    async def test_handle_token_refresh_failure(self, handler, mock_connection):
        """Test failed token refresh."""
        refresh_token = "invalid-refresh-token"
        
        # Mock current auth
        current_payload = TokenPayload(
            sub=mock_connection.user_id,
            tenant_id=mock_connection.tenant_id,
            session_id=mock_connection.session_id,
            scopes=["read"],
            iat=int(datetime.utcnow().timestamp()),
            exp=int((datetime.utcnow() + timedelta(minutes=5)).timestamp()),
            iss="test-issuer",
            aud="test-audience"
        )
        
        with patch.object(
            handler._authenticator,
            'get_connection_auth',
            return_value=current_payload
        ):
            # Mock JWT error
            with patch.object(
                handler.jwt_manager,
                'refresh_access_token',
                side_effect=Exception("Invalid refresh token")
            ):
                # Mock connection manager
                with patch.object(
                    handler.connection_manager,
                    'send_to_connection',
                    return_value=True
                ) as mock_send:
                    # Attempt refresh
                    result = await handler.handle_token_refresh(
                        mock_connection,
                        refresh_token
                    )
        
        # Verify failure
        assert result is False
        
        # Verify error response sent
        error_calls = [call for call in mock_send.call_args_list
                      if call[0][1].get("type") == "token_refresh_failed"]
        assert len(error_calls) > 0
    
    @pytest.mark.asyncio
    async def test_handle_token_refresh_user_mismatch(self, handler, mock_connection):
        """Test token refresh with user mismatch."""
        refresh_token = "valid-refresh-token"
        
        # Current auth with one user
        current_payload = TokenPayload(
            sub=str(uuid4()),
            tenant_id=mock_connection.tenant_id,
            session_id=mock_connection.session_id,
            scopes=["read"],
            iat=int(datetime.utcnow().timestamp()),
            exp=int((datetime.utcnow() + timedelta(minutes=5)).timestamp()),
            iss="test-issuer",
            aud="test-audience"
        )
        
        # New payload with different user
        new_payload = TokenPayload(
            sub=str(uuid4()),  # Different user!
            tenant_id=mock_connection.tenant_id,
            session_id=mock_connection.session_id,
            scopes=["read"],
            iat=int(datetime.utcnow().timestamp()),
            exp=int((datetime.utcnow() + timedelta(minutes=30)).timestamp()),
            iss="test-issuer",
            aud="test-audience"
        )
        
        with patch.object(
            handler._authenticator,
            'get_connection_auth',
            return_value=current_payload
        ):
            with patch.object(
                handler.jwt_manager,
                'refresh_access_token',
                return_value=("new-token", "new-refresh")
            ):
                with patch.object(
                    handler.jwt_manager,
                    'decode_access_token',
                    return_value=new_payload
                ):
                    # Attempt refresh
                    result = await handler.handle_token_refresh(
                        mock_connection,
                        refresh_token
                    )
        
        # Should fail due to user mismatch
        assert result is False
    
    @pytest.mark.asyncio
    async def test_token_expiration_handling(self, handler, mock_connection):
        """Test handling of token expiration."""
        # Mock connection manager
        with patch.object(
            handler.connection_manager,
            'send_to_connection'
        ) as mock_send:
            with patch.object(
                handler.connection_manager,
                'disconnect'
            ) as mock_disconnect:
                # Handle expiration
                await handler._handle_token_expired(mock_connection)
        
        # Verify expiration message sent
        mock_send.assert_called()
        message = mock_send.call_args[0][1]
        assert message["type"] == "token_expired"
        assert "Authentication token expired" in message["message"]
        
        # Verify disconnect called
        mock_disconnect.assert_called_once_with(
            mock_connection.id,
            close_code=1008,
            reason="Token expired"
        )
    
    @pytest.mark.asyncio
    async def test_multiple_timer_restarts(self, handler, mock_connection, token_payload):
        """Test that starting timer multiple times cancels previous timer."""
        # Start timer
        await handler.start_refresh_timer(mock_connection, token_payload)
        first_task = handler._refresh_tasks[mock_connection.id]
        
        # Start again
        await handler.start_refresh_timer(mock_connection, token_payload)
        second_task = handler._refresh_tasks[mock_connection.id]
        
        # Verify tasks are different
        assert second_task != first_task
        
        # Wait a bit for the cancellation to propagate
        await asyncio.sleep(0.1)
        
        # Verify first task was cancelled
        assert first_task.cancelled() or first_task.done()
        
        # Cleanup
        await handler.stop_refresh_timer(mock_connection.id)
    
    @pytest.mark.asyncio
    async def test_get_active_timers(self, handler, mock_connection, token_payload):
        """Test getting active timer connection IDs."""
        # Initially empty
        assert len(handler.get_active_timers()) == 0
        
        # Start timer
        await handler.start_refresh_timer(mock_connection, token_payload)
        
        # Should have one timer
        active = handler.get_active_timers()
        assert len(active) == 1
        assert mock_connection.id in active
        
        # Cleanup
        await handler.stop_refresh_timer(mock_connection.id)
        assert len(handler.get_active_timers()) == 0
    
    @pytest.mark.asyncio
    async def test_shutdown(self, handler, mock_connection, token_payload):
        """Test handler shutdown."""
        # Start multiple timers
        connections = []
        for i in range(3):
            ws = Mock(spec=WebSocket)
            ws.client_state = WebSocketState.CONNECTED
            ws.application_state = WebSocketState.CONNECTED
            
            conn = WebSocketConnection(
                id=f"conn-{i}",
                websocket=ws,
                user_id=str(uuid4()),
                tenant_id=str(uuid4()),
                session_id=str(uuid4())
            )
            connections.append(conn)
            await handler.start_refresh_timer(conn, token_payload)
        
        # Verify timers active
        assert len(handler.get_active_timers()) == 3
        
        # Shutdown
        await handler.shutdown()
        
        # Verify all timers stopped
        assert len(handler.get_active_timers()) == 0
        for task in handler._refresh_tasks.values():
            assert task.cancelled() or task.done()


class TestGetTokenRefreshHandler:
    """Test singleton token refresh handler."""
    
    def test_singleton_instance(self):
        """Test get_token_refresh_handler returns singleton."""
        handler1 = get_token_refresh_handler()
        handler2 = get_token_refresh_handler()
        
        assert handler1 is handler2