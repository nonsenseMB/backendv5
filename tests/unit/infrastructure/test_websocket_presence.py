"""
Unit tests for WebSocket presence tracking system.
Tests presence manager, heartbeat, and presence updates.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch, ANY
from datetime import datetime, timedelta
from uuid import uuid4
import asyncio
import json

from src.infrastructure.websocket.presence import PresenceManager, get_presence_manager


class TestPresenceManager:
    """Test presence manager functionality."""
    
    @pytest.fixture
    def presence_manager(self):
        """Create presence manager instance."""
        return PresenceManager()
    
    @pytest.fixture
    def mock_redis(self):
        """Create mock Redis client."""
        redis = Mock()
        redis.setex = AsyncMock()
        redis.get = AsyncMock()
        redis.delete = AsyncMock()
        redis.publish = AsyncMock()
        redis.keys = AsyncMock()
        redis.pipeline = Mock()
        redis.pubsub = Mock()
        return redis
    
    @pytest.mark.asyncio
    async def test_update_presence_with_redis(self, presence_manager, mock_redis):
        """Test updating presence with Redis."""
        presence_manager.redis = mock_redis
        
        user_id = str(uuid4())
        tenant_id = str(uuid4())
        status = "online"
        
        # Update presence
        result = await presence_manager.update_presence(
            user_id, tenant_id, status
        )
        
        assert result is True
        
        # Verify Redis calls
        mock_redis.setex.assert_called_once()
        call_args = mock_redis.setex.call_args[0]
        assert call_args[0] == f"presence:{tenant_id}:{user_id}"
        assert call_args[1] == presence_manager.ttl
        
        # Verify published event
        mock_redis.publish.assert_called_once_with(
            f"presence:{tenant_id}",
            ANY
        )
    
    @pytest.mark.asyncio
    async def test_update_presence_without_redis(self, presence_manager):
        """Test updating presence without Redis (local fallback)."""
        presence_manager.redis = None
        
        user_id = str(uuid4())
        tenant_id = str(uuid4())
        status = "away"
        
        # Update presence
        result = await presence_manager.update_presence(
            user_id, tenant_id, status
        )
        
        assert result is True
        
        # Verify local storage
        key = f"presence:{tenant_id}:{user_id}"
        assert key in presence_manager._local_presence
        assert presence_manager._local_presence[key]["status"] == status
    
    @pytest.mark.asyncio
    async def test_get_user_presence_from_redis(self, presence_manager, mock_redis):
        """Test getting user presence from Redis."""
        presence_manager.redis = mock_redis
        
        user_id = str(uuid4())
        tenant_id = str(uuid4())
        
        # Mock Redis response
        presence_data = {
            "user_id": user_id,
            "tenant_id": tenant_id,
            "status": "online",
            "last_seen": datetime.utcnow().isoformat()
        }
        mock_redis.get.return_value = json.dumps(presence_data)
        
        # Get presence
        result = await presence_manager.get_user_presence(user_id, tenant_id)
        
        assert result is not None
        assert result["status"] == "online"
        assert result["user_id"] == user_id
    
    @pytest.mark.asyncio
    async def test_get_user_presence_expired(self, presence_manager):
        """Test getting expired user presence from local storage."""
        presence_manager.redis = None
        
        user_id = str(uuid4())
        tenant_id = str(uuid4())
        key = f"presence:{tenant_id}:{user_id}"
        
        # Add expired presence (more than ttl seconds ago)
        presence_manager._local_presence[key] = {
            "user_id": user_id,
            "status": "online",
            "last_seen": (datetime.utcnow() - timedelta(seconds=presence_manager.ttl + 10)).isoformat()
        }
        
        # Mock _ensure_redis to not throw exceptions
        with patch.object(presence_manager, '_ensure_redis', new=AsyncMock()):
            # Get presence (should be None - expired)
            result = await presence_manager.get_user_presence(user_id, tenant_id)
            
            assert result is None
            # The key should be removed after accessing expired entry
            assert key not in presence_manager._local_presence
    
    @pytest.mark.asyncio
    async def test_get_online_users_with_redis(self, presence_manager, mock_redis):
        """Test getting online users with Redis."""
        presence_manager.redis = mock_redis
        
        tenant_id = str(uuid4())
        
        # Mock Redis keys
        keys = [
            f"presence:{tenant_id}:user1",
            f"presence:{tenant_id}:user2"
        ]
        mock_redis.keys.return_value = keys
        
        # Mock presence data
        presence1 = {
            "user_id": "user1",
            "status": "online",
            "last_seen": datetime.utcnow().isoformat()
        }
        presence2 = {
            "user_id": "user2",
            "status": "away",
            "last_seen": datetime.utcnow().isoformat()
        }
        
        mock_redis.get.side_effect = [
            json.dumps(presence1),
            json.dumps(presence2)
        ]
        
        # Get online users
        result = await presence_manager.get_online_users(tenant_id)
        
        assert len(result) == 2
        assert result[0]["user_id"] == "user1"
        assert result[1]["user_id"] == "user2"
    
    @pytest.mark.asyncio
    async def test_get_online_users_local(self, presence_manager):
        """Test getting online users from local storage."""
        presence_manager.redis = None
        
        tenant_id = str(uuid4())
        now = datetime.utcnow()
        
        # Add local presence data
        presence_manager._local_presence[f"presence:{tenant_id}:user1"] = {
            "user_id": "user1",
            "tenant_id": tenant_id,
            "status": "online",
            "last_seen": now.isoformat(),
            "metadata": {}
        }
        presence_manager._local_presence[f"presence:{tenant_id}:user2"] = {
            "user_id": "user2",
            "tenant_id": tenant_id,
            "status": "away",  # Should be included with include_away=True
            "last_seen": now.isoformat(),
            "metadata": {}
        }
        presence_manager._local_presence[f"presence:other:user3"] = {
            "user_id": "user3",
            "tenant_id": "other",
            "status": "online",
            "last_seen": now.isoformat(),
            "metadata": {}
        }
        
        # Mock _ensure_redis to not throw exceptions
        with patch.object(presence_manager, '_ensure_redis', new=AsyncMock()):
            # Get online users (include_away=True by default)
            result = await presence_manager.get_online_users(tenant_id)
            
            assert len(result) == 2  # user1 (online) and user2 (away)
            user_ids = [r["user_id"] for r in result]
            assert "user1" in user_ids
            assert "user2" in user_ids
            assert "user3" not in user_ids  # Different tenant
    
    @pytest.mark.asyncio
    async def test_remove_presence(self, presence_manager, mock_redis):
        """Test removing user presence."""
        presence_manager.redis = mock_redis
        
        user_id = str(uuid4())
        tenant_id = str(uuid4())
        
        # Remove presence
        await presence_manager.remove_presence(user_id, tenant_id)
        
        # Verify offline update was published
        assert mock_redis.publish.call_count == 1
        publish_call = mock_redis.publish.call_args[0]
        assert publish_call[0] == f"presence:{tenant_id}"
        data = json.loads(publish_call[1])
        assert data["status"] == "offline"
        
        # Verify deletion
        mock_redis.delete.assert_called_once_with(
            f"presence:{tenant_id}:{user_id}"
        )
    
    @pytest.mark.asyncio
    async def test_heartbeat_lifecycle(self, presence_manager, mock_redis):
        """Test presence heartbeat start/stop."""
        presence_manager.redis = mock_redis
        
        user_id = str(uuid4())
        tenant_id = str(uuid4())
        connection_id = str(uuid4())
        
        # Start heartbeat
        await presence_manager.start_heartbeat(user_id, tenant_id, connection_id)
        
        # Verify task created
        assert connection_id in presence_manager._presence_tasks
        task = presence_manager._presence_tasks[connection_id]
        assert not task.done()
        
        # Stop heartbeat
        await presence_manager.stop_heartbeat(connection_id)
        
        # Wait a bit for task to be cancelled
        await asyncio.sleep(0.1)
        
        # Verify task cancelled
        assert connection_id not in presence_manager._presence_tasks
        assert task.cancelled() or task.done()
    
    @pytest.mark.asyncio
    async def test_heartbeat_updates_presence(self, presence_manager, mock_redis):
        """Test heartbeat updates presence periodically."""
        presence_manager.redis = mock_redis
        presence_manager.heartbeat_interval = 0.1  # Fast for testing
        
        user_id = str(uuid4())
        tenant_id = str(uuid4())
        connection_id = str(uuid4())
        
        # Start heartbeat
        await presence_manager.start_heartbeat(user_id, tenant_id, connection_id)
        
        # Wait for a few heartbeats
        await asyncio.sleep(0.3)
        
        # Stop heartbeat
        await presence_manager.stop_heartbeat(connection_id)
        
        # Verify multiple presence updates
        assert mock_redis.setex.call_count >= 2
    
    @pytest.mark.asyncio
    async def test_get_presence_summary(self, presence_manager, mock_redis):
        """Test getting presence summary."""
        presence_manager.redis = mock_redis
        
        tenant_id = str(uuid4())
        
        # Mock Redis keys
        keys = [
            f"presence:{tenant_id}:user1",
            f"presence:{tenant_id}:user2",
            f"presence:{tenant_id}:user3"
        ]
        mock_redis.keys.return_value = keys
        
        # Mock presence data
        mock_redis.get.side_effect = [
            json.dumps({"status": "online"}),
            json.dumps({"status": "online"}),
            json.dumps({"status": "away"})
        ]
        
        # Get summary
        result = await presence_manager.get_presence_summary(tenant_id)
        
        assert result["online"] == 2
        assert result["away"] == 1
        assert result["busy"] == 0
        assert result["offline"] == 0
    
    @pytest.mark.asyncio
    async def test_cleanup_expired_presence(self, presence_manager):
        """Test cleanup of expired presence entries."""
        presence_manager.redis = None
        
        now = datetime.utcnow()
        
        # Add mix of expired and valid presence
        presence_manager._local_presence["key1"] = {
            "last_seen": (now - timedelta(minutes=5)).isoformat()  # Expired
        }
        presence_manager._local_presence["key2"] = {
            "last_seen": now.isoformat()  # Valid
        }
        presence_manager._local_presence["key3"] = {
            "last_seen": (now - timedelta(seconds=10)).isoformat()  # Valid
        }
        
        # Cleanup
        await presence_manager.cleanup_expired_presence()
        
        # Verify only expired removed
        assert "key1" not in presence_manager._local_presence
        assert "key2" in presence_manager._local_presence
        assert "key3" in presence_manager._local_presence
    
    @pytest.mark.asyncio
    async def test_shutdown(self, presence_manager):
        """Test presence manager shutdown."""
        # Start some heartbeats
        tasks = []
        for i in range(3):
            connection_id = f"conn-{i}"
            await presence_manager.start_heartbeat(
                f"user-{i}",
                "tenant",
                connection_id
            )
            tasks.append(presence_manager._presence_tasks[connection_id])
        
        # Shutdown
        await presence_manager.shutdown()
        
        # Verify all cleaned up
        assert len(presence_manager._presence_tasks) == 0
        assert len(presence_manager._local_presence) == 0
        
        # Verify tasks cancelled
        for task in tasks:
            assert task.cancelled() or task.done()


class TestPresenceIntegration:
    """Test presence integration with connection manager."""
    
    @pytest.mark.asyncio
    async def test_connection_updates_presence(self):
        """Test that connecting updates presence."""
        from src.infrastructure.websocket.connection_manager import EnhancedConnectionManager
        
        # Mock dependencies
        with patch('src.infrastructure.websocket.connection_manager.get_redis_client') as mock_redis:
            with patch('src.infrastructure.websocket.connection_manager.get_presence_manager') as mock_pm:
                mock_redis.return_value = AsyncMock()
                presence_manager = Mock()
                presence_manager.update_presence = AsyncMock(return_value=True)
                presence_manager.start_heartbeat = AsyncMock()
                mock_pm.return_value = presence_manager
                
                # Create connection manager
                manager = EnhancedConnectionManager()
                
                # Mock WebSocket
                ws = Mock()
                ws.accept = AsyncMock()
                
                # Connect
                connection = await manager.connect(
                    websocket=ws,
                    user_id=str(uuid4()),
                    tenant_id=str(uuid4()),
                    session_id=str(uuid4())
                )
                
                # Verify presence updated
                presence_manager.update_presence.assert_called_once()
                presence_manager.start_heartbeat.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_disconnect_updates_presence(self):
        """Test that disconnecting updates presence."""
        from src.infrastructure.websocket.connection_manager import EnhancedConnectionManager
        
        with patch('src.infrastructure.websocket.connection_manager.get_redis_client') as mock_redis:
            with patch('src.infrastructure.websocket.connection_manager.get_presence_manager') as mock_pm:
                mock_redis.return_value = AsyncMock()
                presence_manager = Mock()
                presence_manager.update_presence = AsyncMock(return_value=True)
                presence_manager.start_heartbeat = AsyncMock()
                presence_manager.stop_heartbeat = AsyncMock()
                presence_manager.remove_presence = AsyncMock()
                mock_pm.return_value = presence_manager
                
                # Create connection manager
                manager = EnhancedConnectionManager()
                
                # Mock WebSocket
                ws = Mock()
                ws.accept = AsyncMock()
                ws.close = AsyncMock()
                
                # Connect first
                connection = await manager.connect(
                    websocket=ws,
                    user_id=str(uuid4()),
                    tenant_id=str(uuid4()),
                    session_id=str(uuid4())
                )
                
                # Disconnect
                await manager.disconnect(connection.id)
                
                # Verify presence updated
                presence_manager.stop_heartbeat.assert_called_once_with(connection.id)
                presence_manager.remove_presence.assert_called_once()


class TestGetPresenceManager:
    """Test singleton presence manager."""
    
    def test_singleton_instance(self):
        """Test get_presence_manager returns singleton."""
        manager1 = get_presence_manager()
        manager2 = get_presence_manager()
        assert manager1 is manager2