"""
Unit tests for enhanced WebSocket connection manager.
Tests connection lifecycle, channel management, and distributed state.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta
from uuid import uuid4
import asyncio
import json

from fastapi import WebSocket
from starlette.websockets import WebSocketState

from src.infrastructure.websocket.connection_manager import (
    EnhancedConnectionManager,
    WebSocketConnection,
    get_connection_manager
)
from src.infrastructure.websocket.connection_state import (
    ConnectionStatus,
    ConnectionMetadata,
    RateLimitAction
)


class TestEnhancedConnectionManager:
    """Test enhanced connection manager functionality."""
    
    @pytest.fixture
    def manager(self):
        """Create connection manager instance."""
        return EnhancedConnectionManager(server_id="test-server")
    
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
    def connection_params(self):
        """Common connection parameters."""
        return {
            "user_id": str(uuid4()),
            "tenant_id": str(uuid4()),
            "session_id": str(uuid4()),
            "device_id": "test-device"
        }
    
    @pytest.mark.asyncio
    async def test_manager_initialization(self, manager):
        """Test manager initializes correctly."""
        assert manager.server_id == "test-server"
        assert manager.max_connections_per_user == 5
        assert manager.max_connections_per_tenant == 1000
        assert manager.connection_timeout == 3600
        assert manager.heartbeat_interval == 30
        
        # Initialize and check tasks started
        await manager.initialize()
        assert manager._cleanup_task is not None
        assert manager._sync_task is not None
        
        # Cleanup
        await manager.shutdown()
    
    @pytest.mark.asyncio
    async def test_connect_success(self, manager, mock_websocket, connection_params):
        """Test successful connection."""
        # Mock Redis
        with patch('src.infrastructure.websocket.connection_manager.get_redis_client') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            # Mock audit logging
            with patch('src.infrastructure.websocket.connection_manager.get_async_session') as mock_session:
                mock_session.return_value.__aiter__.return_value = [Mock()]
                with patch('src.infrastructure.websocket.connection_manager.AuthAuditService'):
                    # Connect
                    connection = await manager.connect(
                        mock_websocket,
                        **connection_params
                    )
        
        # Verify connection created
        assert connection is not None
        assert connection.user_id == connection_params["user_id"]
        assert connection.tenant_id == connection_params["tenant_id"]
        assert connection.device_id == connection_params["device_id"]
        assert connection.status == ConnectionStatus.AUTHENTICATED
        
        # Verify connection stored
        assert connection.id in manager._connections
        assert connection.id in manager._user_connections[connection_params["user_id"]]
        assert connection.id in manager._tenant_connections[connection_params["tenant_id"]]
        
        # Verify metadata created
        metadata = manager.get_metadata(connection.id)
        assert metadata is not None
        assert metadata.user_id == connection_params["user_id"]
        
        # Verify default channels joined
        assert f"user:{connection_params['user_id']}" in metadata.channels
        assert f"tenant:{connection_params['tenant_id']}" in metadata.channels
    
    @pytest.mark.asyncio
    async def test_connect_user_limit_exceeded(self, manager, mock_websocket, connection_params):
        """Test connection fails when user limit exceeded."""
        manager.max_connections_per_user = 2
        
        # Mock Redis
        with patch('src.infrastructure.websocket.connection_manager.get_redis_client') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            # Mock audit
            with patch('src.infrastructure.websocket.connection_manager.get_async_session') as mock_session:
                mock_session.return_value.__aiter__.return_value = [Mock()]
                with patch('src.infrastructure.websocket.connection_manager.AuthAuditService'):
                    # Create max connections
                    for i in range(2):
                        ws = Mock(spec=WebSocket)
                        ws.client_state = WebSocketState.CONNECTED
                        ws.application_state = WebSocketState.CONNECTED
                        await manager.connect(ws, **connection_params)
                    
                    # Next should fail
                    with pytest.raises(ConnectionError, match="User connection limit exceeded"):
                        await manager.connect(mock_websocket, **connection_params)
    
    @pytest.mark.asyncio
    async def test_disconnect(self, manager, mock_websocket, connection_params):
        """Test disconnection and cleanup."""
        # Connect first
        with patch('src.infrastructure.websocket.connection_manager.get_redis_client') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            with patch('src.infrastructure.websocket.connection_manager.get_async_session') as mock_session:
                mock_session.return_value.__aiter__.return_value = [Mock()]
                with patch('src.infrastructure.websocket.connection_manager.AuthAuditService'):
                    connection = await manager.connect(mock_websocket, **connection_params)
                    connection_id = connection.id
                    
                    # Join additional channel
                    await manager.join_channel(connection_id, "test:channel")
                    
                    # Disconnect
                    await manager.disconnect(connection_id, "Test disconnect")
        
        # Verify cleanup
        assert connection_id not in manager._connections
        assert connection_id not in manager._metadata
        assert connection_params["user_id"] not in manager._user_connections
        assert connection_params["tenant_id"] not in manager._tenant_connections
        
        # Verify WebSocket closed
        mock_websocket.close.assert_called_once_with(code=1000, reason="Test disconnect")
    
    @pytest.mark.asyncio
    async def test_send_to_connection(self, manager, mock_websocket, connection_params):
        """Test sending message to connection."""
        # Connect first
        with patch('src.infrastructure.websocket.connection_manager.get_redis_client') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            with patch('src.infrastructure.websocket.connection_manager.get_async_session') as mock_session:
                mock_session.return_value.__aiter__.return_value = [Mock()]
                with patch('src.infrastructure.websocket.connection_manager.AuthAuditService'):
                    connection = await manager.connect(mock_websocket, **connection_params)
        
        # Send message
        message = {"type": "test", "data": "hello"}
        result = await manager.send_to_connection(connection.id, message)
        
        # Verify
        assert result is True
        mock_websocket.send_json.assert_called_once_with(message)
        assert connection.stats.messages_sent == 1
        assert connection.stats.bytes_sent > 0
    
    @pytest.mark.asyncio
    async def test_send_to_connection_failed(self, manager, mock_websocket, connection_params):
        """Test handling send failure."""
        # Connect first
        with patch('src.infrastructure.websocket.connection_manager.get_redis_client') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            with patch('src.infrastructure.websocket.connection_manager.get_async_session') as mock_session:
                mock_session.return_value.__aiter__.return_value = [Mock()]
                with patch('src.infrastructure.websocket.connection_manager.AuthAuditService'):
                    connection = await manager.connect(mock_websocket, **connection_params)
        
        # Make send fail
        mock_websocket.send_json.side_effect = Exception("Send failed")
        
        # Send message
        message = {"type": "test", "data": "hello"}
        result = await manager.send_to_connection(connection.id, message)
        
        # Verify
        assert result is False
        assert connection.stats.errors == 1
        assert connection.stats.last_error == "Send failed"
    
    @pytest.mark.asyncio
    async def test_join_channel(self, manager, mock_websocket, connection_params):
        """Test joining a channel."""
        # Connect first
        with patch('src.infrastructure.websocket.connection_manager.get_redis_client') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            with patch('src.infrastructure.websocket.connection_manager.get_async_session') as mock_session:
                mock_session.return_value.__aiter__.return_value = [Mock()]
                with patch('src.infrastructure.websocket.connection_manager.AuthAuditService'):
                    connection = await manager.connect(mock_websocket, **connection_params)
                    
                    # Join conversation channel
                    result = await manager.join_channel(connection.id, "conversation:123")
        
        # Verify
        assert result is True
        metadata = manager.get_metadata(connection.id)
        assert "conversation:123" in metadata.channels
        
        # Verify Redis calls
        mock_redis_client.sadd.assert_any_call(
            "channel:conversation:123:connections", connection.id
        )
        mock_redis_client.sadd.assert_any_call(
            f"connection:{connection.id}:channels", "conversation:123"
        )
    
    @pytest.mark.asyncio
    async def test_join_channel_access_denied(self, manager, mock_websocket, connection_params):
        """Test joining channel with access denied."""
        # Connect first
        with patch('src.infrastructure.websocket.connection_manager.get_redis_client') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            with patch('src.infrastructure.websocket.connection_manager.get_async_session') as mock_session:
                mock_session.return_value.__aiter__.return_value = [Mock()]
                with patch('src.infrastructure.websocket.connection_manager.AuthAuditService'):
                    connection = await manager.connect(mock_websocket, **connection_params)
                    
                    # Try to join another user's channel
                    other_user_id = str(uuid4())
                    result = await manager.join_channel(connection.id, f"user:{other_user_id}")
        
        # Verify denied
        assert result is False
        metadata = manager.get_metadata(connection.id)
        assert f"user:{other_user_id}" not in metadata.channels
    
    @pytest.mark.asyncio
    async def test_leave_channel(self, manager, mock_websocket, connection_params):
        """Test leaving a channel."""
        # Connect and join channel
        with patch('src.infrastructure.websocket.connection_manager.get_redis_client') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            with patch('src.infrastructure.websocket.connection_manager.get_async_session') as mock_session:
                mock_session.return_value.__aiter__.return_value = [Mock()]
                with patch('src.infrastructure.websocket.connection_manager.AuthAuditService'):
                    connection = await manager.connect(mock_websocket, **connection_params)
                    await manager.join_channel(connection.id, "conversation:123")
                    
                    # Leave channel
                    await manager.leave_channel(connection.id, "conversation:123")
        
        # Verify
        metadata = manager.get_metadata(connection.id)
        assert "conversation:123" not in metadata.channels
        
        # Verify Redis calls
        mock_redis_client.srem.assert_any_call(
            "channel:conversation:123:connections", connection.id
        )
    
    @pytest.mark.asyncio
    async def test_broadcast_to_channel(self, manager, mock_websocket, connection_params):
        """Test broadcasting to channel."""
        # Create two connections in same channel
        with patch('src.infrastructure.websocket.connection_manager.get_redis_client') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            with patch('src.infrastructure.websocket.connection_manager.get_async_session') as mock_session:
                mock_session.return_value.__aiter__.return_value = [Mock()]
                with patch('src.infrastructure.websocket.connection_manager.AuthAuditService'):
                    # First connection
                    conn1 = await manager.connect(mock_websocket, **connection_params)
                    await manager.join_channel(conn1.id, "chat:123")
                    
                    # Second connection
                    ws2 = Mock(spec=WebSocket)
                    ws2.send_json = AsyncMock()
                    ws2.client_state = WebSocketState.CONNECTED
                    ws2.application_state = WebSocketState.CONNECTED
                    
                    conn2 = await manager.connect(ws2, **connection_params)
                    await manager.join_channel(conn2.id, "chat:123")
                    
                    # Mock Redis channel members
                    mock_redis_client.smembers.return_value = {conn1.id, conn2.id}
                    
                    # Broadcast message
                    message = {"type": "chat", "text": "Hello"}
                    await manager.broadcast_to_channel("chat:123", message, exclude_connection=conn1.id)
        
        # Verify only conn2 received message
        mock_websocket.send_json.assert_not_called()
        ws2.send_json.assert_called_once_with(message)
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, manager, mock_websocket, connection_params):
        """Test rate limiting functionality."""
        # Connect first
        with patch('src.infrastructure.websocket.connection_manager.get_redis_client') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            with patch('src.infrastructure.websocket.connection_manager.get_async_session') as mock_session:
                mock_session.return_value.__aiter__.return_value = [Mock()]
                with patch('src.infrastructure.websocket.connection_manager.AuthAuditService'):
                    connection = await manager.connect(mock_websocket, **connection_params)
        
        # Test message creation rate limit (10 per minute)
        for i in range(10):
            assert await manager.check_rate_limit(connection.id, RateLimitAction.MESSAGE_CREATE) is True
        
        # 11th should be rate limited
        assert await manager.check_rate_limit(connection.id, RateLimitAction.MESSAGE_CREATE) is False
        
        # Other actions should still work
        assert await manager.check_rate_limit(connection.id, RateLimitAction.SUBSCRIBE) is True
    
    @pytest.mark.asyncio
    async def test_get_online_users(self, manager, mock_websocket):
        """Test getting online users for tenant."""
        tenant_id = str(uuid4())
        user1_id = str(uuid4())
        user2_id = str(uuid4())
        
        with patch('src.infrastructure.websocket.connection_manager.get_redis_client') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            with patch('src.infrastructure.websocket.connection_manager.get_async_session') as mock_session:
                mock_session.return_value.__aiter__.return_value = [Mock()]
                with patch('src.infrastructure.websocket.connection_manager.AuthAuditService'):
                    # Connect two different users
                    await manager.connect(
                        mock_websocket,
                        user_id=user1_id,
                        tenant_id=tenant_id,
                        session_id=str(uuid4())
                    )
                    
                    ws2 = Mock(spec=WebSocket)
                    ws2.client_state = WebSocketState.CONNECTED
                    ws2.application_state = WebSocketState.CONNECTED
                    
                    await manager.connect(
                        ws2,
                        user_id=user2_id,
                        tenant_id=tenant_id,
                        session_id=str(uuid4())
                    )
                    
                    # Connect same user again
                    ws3 = Mock(spec=WebSocket)
                    ws3.client_state = WebSocketState.CONNECTED
                    ws3.application_state = WebSocketState.CONNECTED
                    
                    await manager.connect(
                        ws3,
                        user_id=user1_id,
                        tenant_id=tenant_id,
                        session_id=str(uuid4())
                    )
        
        # Get online users
        online_users = manager.get_online_users(tenant_id)
        assert len(online_users) == 2
        assert user1_id in online_users
        assert user2_id in online_users
    
    @pytest.mark.asyncio
    async def test_connection_stats(self, manager, mock_websocket, connection_params):
        """Test connection statistics tracking."""
        # Connect first
        with patch('src.infrastructure.websocket.connection_manager.get_redis_client') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            with patch('src.infrastructure.websocket.connection_manager.get_async_session') as mock_session:
                mock_session.return_value.__aiter__.return_value = [Mock()]
                with patch('src.infrastructure.websocket.connection_manager.AuthAuditService'):
                    connection = await manager.connect(mock_websocket, **connection_params)
                    
                    # Send some messages
                    await manager.send_to_connection(connection.id, {"type": "test1"})
                    await manager.send_to_connection(connection.id, {"type": "test2"})
                    
                    # Simulate receive
                    connection.stats.record_message_received(100)
                    
                    # Get stats
                    stats = await manager.get_connection_stats(connection.id)
        
        assert stats is not None
        assert stats["messages_sent"] == 2
        assert stats["messages_received"] == 1
        assert stats["bytes_sent"] > 0
        assert stats["bytes_received"] == 100
        assert stats["connection_duration"] > 0
        assert stats["is_connected"] is True


class TestGetConnectionManager:
    """Test connection manager singleton."""
    
    @pytest.mark.asyncio
    async def test_singleton_instance(self):
        """Test get_connection_manager returns singleton."""
        with patch('src.infrastructure.websocket.connection_manager.EnhancedConnectionManager.initialize'):
            manager1 = await get_connection_manager()
            manager2 = await get_connection_manager()
            
            assert manager1 is manager2