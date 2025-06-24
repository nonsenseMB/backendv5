"""
Unit tests for WebSocket permission system.
Tests permission decorators, rate limiting, and permission checks.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime
from uuid import uuid4
import asyncio

from fastapi import WebSocket
from starlette.websockets import WebSocketState

from src.api.websocket.permissions import (
    WebSocketPermissionManager,
    WebSocketRateLimiter,
    get_permission_manager,
    get_rate_limiter
)
from src.api.websocket.decorators import (
    require_ws_permission,
    require_ws_resource_permission,
    rate_limit,
    combine_decorators
)
from src.infrastructure.websocket.connection_manager import WebSocketConnection
from src.infrastructure.websocket.connection_state import ConnectionMetadata


class TestWebSocketPermissionManager:
    """Test permission manager functionality."""
    
    @pytest.fixture
    def permission_manager(self):
        """Create permission manager instance."""
        return WebSocketPermissionManager()
    
    @pytest.mark.asyncio
    async def test_check_permission_granted(self, permission_manager):
        """Test permission check when granted."""
        user_id = str(uuid4())
        tenant_id = str(uuid4())
        permission = "channel.subscribe"
        
        # Mock database session and permission checker
        with patch('src.api.websocket.permissions.get_async_session') as mock_session:
            mock_db = Mock()
            mock_session.return_value = AsyncMock()
            mock_session.return_value.__aiter__.return_value = [mock_db]
            
            with patch('src.api.websocket.permissions.PermissionChecker') as mock_checker:
                mock_checker.return_value.check_permission = AsyncMock(return_value=True)
                
                # Check permission
                result = await permission_manager.check_permission(
                    user_id, tenant_id, permission
                )
                
                assert result is True
                mock_checker.return_value.check_permission.assert_called_once_with(
                    user_id=user_id,
                    tenant_id=tenant_id,
                    permission=permission
                )
    
    @pytest.mark.asyncio
    async def test_check_permission_denied(self, permission_manager):
        """Test permission check when denied."""
        user_id = str(uuid4())
        tenant_id = str(uuid4())
        permission = "admin.write"
        
        with patch('src.api.websocket.permissions.get_async_session') as mock_session:
            mock_db = Mock()
            mock_session.return_value = AsyncMock()
            mock_session.return_value.__aiter__.return_value = [mock_db]
            
            with patch('src.api.websocket.permissions.PermissionChecker') as mock_checker:
                mock_checker.return_value.check_permission = AsyncMock(return_value=False)
                
                result = await permission_manager.check_permission(
                    user_id, tenant_id, permission
                )
                
                assert result is False
    
    @pytest.mark.asyncio
    async def test_permission_cache(self, permission_manager):
        """Test permission caching."""
        user_id = str(uuid4())
        tenant_id = str(uuid4())
        permission = "read"
        
        with patch('src.api.websocket.permissions.get_async_session') as mock_session:
            mock_db = Mock()
            mock_session.return_value = AsyncMock()
            mock_session.return_value.__aiter__.return_value = [mock_db]
            
            with patch('src.api.websocket.permissions.PermissionChecker') as mock_checker:
                mock_checker.return_value.check_permission = AsyncMock(return_value=True)
                
                # First call - hits database
                result1 = await permission_manager.check_permission(
                    user_id, tenant_id, permission
                )
                assert result1 is True
                assert mock_checker.return_value.check_permission.call_count == 1
                
                # Second call - uses cache
                result2 = await permission_manager.check_permission(
                    user_id, tenant_id, permission
                )
                assert result2 is True
                assert mock_checker.return_value.check_permission.call_count == 1
    
    @pytest.mark.asyncio
    async def test_check_resource_permission(self, permission_manager):
        """Test resource-specific permission check."""
        user_id = str(uuid4())
        tenant_id = str(uuid4())
        resource_type = "conversation"
        resource_id = str(uuid4())
        permission = "conversation.read"
        
        with patch('src.api.websocket.permissions.get_async_session') as mock_session:
            mock_db = Mock()
            mock_session.return_value = AsyncMock()
            mock_session.return_value.__aiter__.return_value = [mock_db]
            
            with patch('src.api.websocket.permissions.PermissionChecker') as mock_checker:
                mock_checker.return_value.check_resource_permission = AsyncMock(return_value=True)
                
                result = await permission_manager.check_resource_permission(
                    user_id, tenant_id, resource_type, resource_id, permission
                )
                
                assert result is True
                mock_checker.return_value.check_resource_permission.assert_called_once_with(
                    user_id=user_id,
                    tenant_id=tenant_id,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    permission=permission
                )
    
    def test_clear_cache(self, permission_manager):
        """Test cache clearing."""
        user_id = str(uuid4())
        tenant_id = str(uuid4())
        cache_key = f"{user_id}:{tenant_id}"
        
        # Add to cache
        permission_manager._permission_cache[cache_key] = {"permissions": {"read"}}
        permission_manager._cache_timestamps[cache_key] = 123456
        
        # Clear cache
        permission_manager.clear_cache(user_id, tenant_id)
        
        assert cache_key not in permission_manager._permission_cache
        assert cache_key not in permission_manager._cache_timestamps


class TestWebSocketRateLimiter:
    """Test rate limiter functionality."""
    
    @pytest.fixture
    def rate_limiter(self):
        """Create rate limiter instance."""
        return WebSocketRateLimiter()
    
    @pytest.mark.asyncio
    async def test_rate_limit_allows_within_limit(self, rate_limiter):
        """Test rate limiting allows requests within limit."""
        connection_id = str(uuid4())
        action = "message.create"
        
        # Mock Redis to simulate failure (force local rate limiting)
        with patch.object(rate_limiter, '_ensure_redis', side_effect=Exception("Redis error")):
            # Should allow first 10 requests (limit is 10 per 60 seconds)
            for i in range(10):
                result = await rate_limiter.check_rate_limit(connection_id, action)
                assert result is True
    
    @pytest.mark.asyncio
    async def test_rate_limit_blocks_over_limit(self, rate_limiter):
        """Test rate limiting blocks requests over limit."""
        connection_id = str(uuid4())
        action = "message.create"
        
        # Mock Redis to simulate failure (force local rate limiting)
        with patch.object(rate_limiter, '_ensure_redis', side_effect=Exception("Redis error")):
            # Use up all tokens
            for i in range(10):
                await rate_limiter.check_rate_limit(connection_id, action)
            
            # 11th request should be blocked
            result = await rate_limiter.check_rate_limit(connection_id, action)
            assert result is False
    
    @pytest.mark.asyncio
    async def test_rate_limit_with_redis(self, rate_limiter):
        """Test rate limiting with Redis."""
        connection_id = str(uuid4())
        action = "subscribe"
        
        # Mock Redis client
        mock_redis = Mock()
        mock_pipe = Mock()
        mock_redis.pipeline.return_value = mock_pipe
        mock_pipe.incr = Mock()
        mock_pipe.expire = Mock()
        mock_pipe.execute = AsyncMock(return_value=[1, True])  # First request
        
        rate_limiter.redis_client = mock_redis
        
        # First request should pass
        result = await rate_limiter.check_rate_limit(connection_id, action)
        assert result is True
        
        # Verify Redis was called
        mock_redis.pipeline.assert_called()
        mock_pipe.incr.assert_called_with(f"ws_rate:{connection_id}:{action}")
        mock_pipe.expire.assert_called_with(f"ws_rate:{connection_id}:{action}", 60)
    
    @pytest.mark.asyncio
    async def test_rate_limit_custom_action(self, rate_limiter):
        """Test rate limiting with custom action uses default limit."""
        connection_id = str(uuid4())
        action = "custom_action"
        
        # Mock Redis to simulate failure (force local rate limiting)
        with patch.object(rate_limiter, '_ensure_redis', side_effect=Exception("Redis error")):
            # Should use default limit (100 per 60 seconds)
            for i in range(100):
                result = await rate_limiter.check_rate_limit(connection_id, action)
                assert result is True
            
            # 101st request should be blocked
            result = await rate_limiter.check_rate_limit(connection_id, action)
            assert result is False
    
    def test_reset_connection(self, rate_limiter):
        """Test resetting connection rate limits."""
        connection_id = str(uuid4())
        
        # Add some buckets
        rate_limiter._local_buckets[f"{connection_id}:action1"] = {"tokens": 5}
        rate_limiter._local_buckets[f"{connection_id}:action2"] = {"tokens": 10}
        rate_limiter._local_buckets["other:action"] = {"tokens": 15}
        
        # Reset connection
        rate_limiter.reset_connection(connection_id)
        
        # Only connection's buckets should be removed
        assert f"{connection_id}:action1" not in rate_limiter._local_buckets
        assert f"{connection_id}:action2" not in rate_limiter._local_buckets
        assert "other:action" in rate_limiter._local_buckets


class TestWebSocketDecorators:
    """Test WebSocket decorators."""
    
    @pytest.fixture
    def mock_connection(self):
        """Create mock WebSocket connection."""
        ws = Mock(spec=WebSocket)
        ws.send_json = AsyncMock()
        ws.close = AsyncMock()
        ws.client_state = WebSocketState.CONNECTED
        ws.application_state = WebSocketState.CONNECTED
        
        connection = WebSocketConnection(
            id=str(uuid4()),
            websocket=ws,
            user_id=str(uuid4()),
            tenant_id=str(uuid4()),
            session_id=str(uuid4())
        )
        return connection
    
    @pytest.fixture
    def mock_metadata(self, mock_connection):
        """Create mock connection metadata."""
        return ConnectionMetadata(
            user_id=mock_connection.user_id,
            tenant_id=mock_connection.tenant_id,
            session_id=mock_connection.session_id
        )
    
    @pytest.mark.asyncio
    async def test_require_ws_permission_granted(self, mock_connection, mock_metadata):
        """Test permission decorator when permission is granted."""
        # Create decorated handler
        @require_ws_permission("test.read")
        async def handler(connection, message):
            return "success"
        
        # Mock connection manager and permission manager
        with patch('src.api.websocket.decorators.get_connection_manager') as mock_cm:
            mock_cm.return_value.get_metadata.return_value = mock_metadata
            
            with patch('src.api.websocket.decorators.get_permission_manager') as mock_pm:
                mock_pm.return_value.check_permission = AsyncMock(return_value=True)
                
                # Call handler
                result = await handler(mock_connection, {"test": "data"})
                assert result == "success"
    
    @pytest.mark.asyncio
    async def test_require_ws_permission_denied(self, mock_connection, mock_metadata):
        """Test permission decorator when permission is denied."""
        @require_ws_permission("admin.write")
        async def handler(connection, message):
            return "should not reach here"
        
        with patch('src.api.websocket.decorators.get_connection_manager') as mock_cm:
            mock_cm.return_value.get_metadata.return_value = mock_metadata
            
            with patch('src.api.websocket.decorators.get_permission_manager') as mock_pm:
                mock_pm.return_value.check_permission = AsyncMock(return_value=False)
                
                # Call handler
                result = await handler(mock_connection, {"test": "data"})
                
                # Should send error message
                mock_connection.websocket.send_json.assert_called_once()
                error_msg = mock_connection.websocket.send_json.call_args[0][0]
                assert error_msg["type"] == "error"
                assert error_msg["error"] == "insufficient_permissions"
                assert result is None
    
    @pytest.mark.asyncio
    async def test_require_ws_resource_permission(self, mock_connection, mock_metadata):
        """Test resource permission decorator."""
        @require_ws_resource_permission("document", "doc_id", "write")
        async def handler(connection, message):
            return "success"
        
        with patch('src.api.websocket.decorators.get_connection_manager') as mock_cm:
            mock_cm.return_value.get_metadata.return_value = mock_metadata
            
            with patch('src.api.websocket.decorators.get_permission_manager') as mock_pm:
                mock_pm.return_value.check_resource_permission = AsyncMock(return_value=True)
                
                # Call handler with resource ID
                result = await handler(mock_connection, {"doc_id": "123"})
                assert result == "success"
                
                # Verify permission check
                mock_pm.return_value.check_resource_permission.assert_called_once_with(
                    user_id=mock_metadata.user_id,
                    tenant_id=mock_metadata.tenant_id,
                    resource_type="document",
                    resource_id="123",
                    permission="document.write"
                )
    
    @pytest.mark.asyncio
    async def test_rate_limit_decorator(self, mock_connection):
        """Test rate limit decorator."""
        @rate_limit("test_action")
        async def handler(connection, message):
            return "success"
        
        with patch('src.api.websocket.decorators.get_rate_limiter') as mock_rl:
            # First call allowed
            mock_rl.return_value.check_rate_limit = AsyncMock(return_value=True)
            result1 = await handler(mock_connection, {"test": "data"})
            assert result1 == "success"
            
            # Second call blocked
            mock_rl.return_value.check_rate_limit = AsyncMock(return_value=False)
            result2 = await handler(mock_connection, {"test": "data"})
            assert result2 is None
            
            # Should send rate limit error
            error_msg = mock_connection.websocket.send_json.call_args[0][0]
            assert error_msg["type"] == "error"
            assert error_msg["error"] == "rate_limit_exceeded"
    
    @pytest.mark.asyncio
    async def test_combine_decorators(self, mock_connection, mock_metadata):
        """Test combining multiple decorators."""
        @combine_decorators(
            rate_limit("test_action"),
            require_ws_permission("test.read")
        )
        async def handler(connection, message):
            return "success"
        
        # Mock both rate limiter and permission manager
        with patch('src.api.websocket.decorators.get_rate_limiter') as mock_rl:
            mock_rl.return_value.check_rate_limit = AsyncMock(return_value=True)
            
            with patch('src.api.websocket.decorators.get_connection_manager') as mock_cm:
                mock_cm.return_value.get_metadata.return_value = mock_metadata
                
                with patch('src.api.websocket.decorators.get_permission_manager') as mock_pm:
                    mock_pm.return_value.check_permission = AsyncMock(return_value=True)
                    
                    # Should pass both checks
                    result = await handler(mock_connection, {"test": "data"})
                    assert result == "success"


class TestSingletonInstances:
    """Test singleton pattern for managers."""
    
    def test_permission_manager_singleton(self):
        """Test get_permission_manager returns singleton."""
        manager1 = get_permission_manager()
        manager2 = get_permission_manager()
        assert manager1 is manager2
    
    def test_rate_limiter_singleton(self):
        """Test get_rate_limiter returns singleton."""
        limiter1 = get_rate_limiter()
        limiter2 = get_rate_limiter()
        assert limiter1 is limiter2