"""
Unit tests for WebSocket connection state management.
Tests connection metadata, rate limiting, and state tracking.
"""

import pytest
from datetime import datetime, timedelta
import time

from src.infrastructure.websocket.connection_state import (
    ConnectionStatus,
    RateLimitAction,
    RateLimitBucket,
    RateLimitState,
    ConnectionMetadata,
    ConnectionStats,
    DistributedConnectionInfo
)


class TestRateLimitBucket:
    """Test rate limit bucket functionality."""
    
    def test_bucket_initialization(self):
        """Test bucket initializes correctly."""
        bucket = RateLimitBucket(
            tokens=10,
            last_refill=time.time(),
            max_tokens=10,
            refill_rate=1.0
        )
        
        assert bucket.tokens == 10
        assert bucket.max_tokens == 10
        assert bucket.refill_rate == 1.0
    
    def test_consume_tokens(self):
        """Test consuming tokens from bucket."""
        bucket = RateLimitBucket(
            tokens=5,
            last_refill=time.time(),
            max_tokens=10,
            refill_rate=1.0
        )
        
        # Should succeed
        assert bucket.consume(3) is True
        assert 1.9 < bucket.tokens < 2.1  # Allow for small refill
        
        # Should fail
        assert bucket.consume(3) is False
        assert 1.9 < bucket.tokens < 2.1
        
        # Should succeed
        assert bucket.consume(2) is True
        assert bucket.tokens < 0.1  # Nearly zero
    
    def test_token_refill(self):
        """Test token refill over time."""
        start_time = time.time()
        bucket = RateLimitBucket(
            tokens=0,
            last_refill=start_time,
            max_tokens=10,
            refill_rate=10.0  # 10 tokens per second
        )
        
        # Wait 0.5 seconds
        time.sleep(0.5)
        
        # Should have ~5 tokens
        assert bucket.consume(4) is True
        assert bucket.tokens < 2  # Some tolerance for timing
        
        # Wait another 0.5 seconds
        time.sleep(0.5)
        
        # Should have more tokens
        assert bucket.consume(5) is True
    
    def test_max_tokens_cap(self):
        """Test tokens don't exceed max."""
        start_time = time.time() - 100  # 100 seconds ago
        bucket = RateLimitBucket(
            tokens=5,
            last_refill=start_time,
            max_tokens=10,
            refill_rate=1.0
        )
        
        # Trigger refill
        bucket.consume(0)
        
        # Should be capped at max
        assert bucket.tokens == 10


class TestRateLimitState:
    """Test rate limit state management."""
    
    def test_default_buckets(self):
        """Test default buckets are created."""
        state = RateLimitState()
        
        # Check all default actions have buckets
        assert RateLimitAction.MESSAGE_CREATE in state.buckets
        assert RateLimitAction.MESSAGE_EDIT in state.buckets
        assert RateLimitAction.SUBSCRIBE in state.buckets
        assert RateLimitAction.DEFAULT in state.buckets
    
    def test_check_rate_limit(self):
        """Test rate limit checking."""
        state = RateLimitState()
        
        # Message creation limited to 10 per minute
        for i in range(10):
            assert state.check_rate_limit(RateLimitAction.MESSAGE_CREATE) is True
        
        # 11th should fail
        assert state.check_rate_limit(RateLimitAction.MESSAGE_CREATE) is False
        
        # Other actions should still work
        assert state.check_rate_limit(RateLimitAction.MESSAGE_EDIT) is True
    
    def test_different_limits(self):
        """Test different actions have different limits."""
        state = RateLimitState()
        
        # File upload limited to 5 per 5 minutes
        for i in range(5):
            assert state.check_rate_limit(RateLimitAction.FILE_UPLOAD) is True
        assert state.check_rate_limit(RateLimitAction.FILE_UPLOAD) is False
        
        # Subscribe limited to 50 per minute
        for i in range(50):
            assert state.check_rate_limit(RateLimitAction.SUBSCRIBE) is True
        assert state.check_rate_limit(RateLimitAction.SUBSCRIBE) is False


class TestConnectionMetadata:
    """Test connection metadata functionality."""
    
    def test_metadata_creation(self):
        """Test creating connection metadata."""
        metadata = ConnectionMetadata(
            user_id="user-123",
            tenant_id="tenant-456",
            session_id="session-789"
        )
        
        assert metadata.user_id == "user-123"
        assert metadata.tenant_id == "tenant-456"
        assert metadata.session_id == "session-789"
        assert len(metadata.channels) == 0
        assert len(metadata.subscriptions) == 0
        assert metadata.permissions is None
    
    def test_channel_management(self):
        """Test channel add/remove."""
        metadata = ConnectionMetadata(
            user_id="user-123",
            tenant_id="tenant-456",
            session_id="session-789"
        )
        
        # Add channels
        metadata.add_channel("chat:123")
        metadata.add_channel("presence:456")
        assert len(metadata.channels) == 2
        assert "chat:123" in metadata.channels
        
        # Remove channel
        metadata.remove_channel("chat:123")
        assert len(metadata.channels) == 1
        assert "chat:123" not in metadata.channels
        
        # Remove non-existent (should not error)
        metadata.remove_channel("chat:999")
        assert len(metadata.channels) == 1
    
    def test_subscription_management(self):
        """Test subscription add/remove."""
        metadata = ConnectionMetadata(
            user_id="user-123",
            tenant_id="tenant-456",
            session_id="session-789"
        )
        
        # Add subscriptions
        metadata.add_subscription("document:123")
        metadata.add_subscription("task:456")
        assert len(metadata.subscriptions) == 2
        
        # Remove subscription
        metadata.remove_subscription("document:123")
        assert len(metadata.subscriptions) == 1
        assert "document:123" not in metadata.subscriptions
    
    def test_permission_management(self):
        """Test permission updates."""
        metadata = ConnectionMetadata(
            user_id="user-123",
            tenant_id="tenant-456",
            session_id="session-789"
        )
        
        # Initially no permissions
        assert metadata.has_permission("read") is False
        
        # Update permissions
        metadata.update_permissions({"read", "write", "admin"})
        assert metadata.has_permission("read") is True
        assert metadata.has_permission("write") is True
        assert metadata.has_permission("delete") is False
        
        # Clear permissions
        metadata.update_permissions(set())
        assert metadata.has_permission("read") is False
    
    def test_serialization(self):
        """Test to_dict and from_dict."""
        metadata = ConnectionMetadata(
            user_id="user-123",
            tenant_id="tenant-456",
            session_id="session-789"
        )
        
        metadata.add_channel("chat:123")
        metadata.add_subscription("doc:456")
        metadata.update_permissions({"read", "write"})
        metadata.custom_data["theme"] = "dark"
        
        # Serialize
        data = metadata.to_dict()
        assert data["user_id"] == "user-123"
        assert "chat:123" in data["channels"]
        assert "doc:456" in data["subscriptions"]
        assert "read" in data["permissions"]
        assert data["custom_data"]["theme"] == "dark"
        
        # Deserialize
        metadata2 = ConnectionMetadata.from_dict(data)
        assert metadata2.user_id == metadata.user_id
        assert metadata2.channels == metadata.channels
        assert metadata2.subscriptions == metadata.subscriptions
        assert metadata2.permissions == metadata.permissions
        assert metadata2.custom_data == metadata.custom_data


class TestConnectionStats:
    """Test connection statistics tracking."""
    
    def test_stats_initialization(self):
        """Test stats initialize to zero."""
        stats = ConnectionStats()
        
        assert stats.messages_sent == 0
        assert stats.messages_received == 0
        assert stats.bytes_sent == 0
        assert stats.bytes_received == 0
        assert stats.errors == 0
        assert stats.last_error is None
        assert stats.last_error_time is None
    
    def test_record_messages(self):
        """Test recording message stats."""
        stats = ConnectionStats()
        
        # Record sent messages
        stats.record_message_sent(100)
        stats.record_message_sent(200)
        assert stats.messages_sent == 2
        assert stats.bytes_sent == 300
        
        # Record received messages
        stats.record_message_received(150)
        assert stats.messages_received == 1
        assert stats.bytes_received == 150
    
    def test_record_errors(self):
        """Test recording errors."""
        stats = ConnectionStats()
        
        # Record error
        stats.record_error("Connection timeout")
        assert stats.errors == 1
        assert stats.last_error == "Connection timeout"
        assert stats.last_error_time is not None
        
        # Record another error
        time.sleep(0.1)
        old_time = stats.last_error_time
        stats.record_error("Invalid message")
        assert stats.errors == 2
        assert stats.last_error == "Invalid message"
        assert stats.last_error_time > old_time
    
    def test_stats_serialization(self):
        """Test stats to_dict."""
        stats = ConnectionStats()
        stats.record_message_sent(100)
        stats.record_message_received(200)
        stats.record_error("Test error")
        
        data = stats.to_dict()
        assert data["messages_sent"] == 1
        assert data["messages_received"] == 1
        assert data["bytes_sent"] == 100
        assert data["bytes_received"] == 200
        assert data["errors"] == 1
        assert data["last_error"] == "Test error"
        assert data["last_error_time"] is not None


class TestDistributedConnectionInfo:
    """Test distributed connection information."""
    
    def test_connection_info_creation(self):
        """Test creating distributed connection info."""
        now = datetime.utcnow()
        info = DistributedConnectionInfo(
            connection_id="conn-123",
            server_id="server-1",
            user_id="user-123",
            tenant_id="tenant-456",
            session_id="session-789",
            device_id="device-abc",
            connected_at=now,
            last_activity=now,
            status=ConnectionStatus.AUTHENTICATED,
            channels={"chat:123", "presence:456"}
        )
        
        assert info.connection_id == "conn-123"
        assert info.server_id == "server-1"
        assert info.status == ConnectionStatus.AUTHENTICATED
        assert len(info.channels) == 2
    
    def test_redis_serialization(self):
        """Test Redis hash serialization."""
        now = datetime.utcnow()
        info = DistributedConnectionInfo(
            connection_id="conn-123",
            server_id="server-1",
            user_id="user-123",
            tenant_id="tenant-456",
            session_id="session-789",
            device_id="device-abc",
            connected_at=now,
            last_activity=now,
            status=ConnectionStatus.CONNECTED,
            channels={"chat:123", "presence:456"}
        )
        
        # Serialize to Redis hash
        redis_data = info.to_redis_hash()
        assert redis_data["connection_id"] == "conn-123"
        assert redis_data["server_id"] == "server-1"
        assert redis_data["status"] == "connected"
        assert redis_data["channels"] == "chat:123,presence:456" or redis_data["channels"] == "presence:456,chat:123"
        assert redis_data["device_id"] == "device-abc"
        
        # Deserialize from Redis hash
        info2 = DistributedConnectionInfo.from_redis_hash(redis_data)
        assert info2.connection_id == info.connection_id
        assert info2.server_id == info.server_id
        assert info2.status == info.status
        assert info2.channels == info.channels
        assert info2.device_id == info.device_id
    
    def test_empty_device_id(self):
        """Test handling empty device ID."""
        now = datetime.utcnow()
        info = DistributedConnectionInfo(
            connection_id="conn-123",
            server_id="server-1",
            user_id="user-123",
            tenant_id="tenant-456",
            session_id="session-789",
            device_id=None,
            connected_at=now,
            last_activity=now,
            status=ConnectionStatus.CONNECTED,
            channels=set()
        )
        
        # Serialize
        redis_data = info.to_redis_hash()
        assert redis_data["device_id"] == ""
        assert redis_data["channels"] == ""
        
        # Deserialize
        info2 = DistributedConnectionInfo.from_redis_hash(redis_data)
        assert info2.device_id is None
        assert len(info2.channels) == 0


class TestConnectionStatus:
    """Test connection status enum."""
    
    def test_status_values(self):
        """Test status enum values."""
        assert ConnectionStatus.CONNECTING.value == "connecting"
        assert ConnectionStatus.CONNECTED.value == "connected"
        assert ConnectionStatus.AUTHENTICATED.value == "authenticated"
        assert ConnectionStatus.DISCONNECTING.value == "disconnecting"
        assert ConnectionStatus.DISCONNECTED.value == "disconnected"
    
    def test_status_comparison(self):
        """Test status comparison."""
        status = ConnectionStatus.CONNECTED
        assert status == ConnectionStatus.CONNECTED
        assert status != ConnectionStatus.DISCONNECTED
        assert status.value == "connected"