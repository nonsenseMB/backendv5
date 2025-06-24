import asyncio
import json
from datetime import datetime
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from src.infrastructure.auth.jwks_cache import JWKSCache
from src.infrastructure.auth.config import AuthentikConfig
from src.infrastructure.auth.exceptions import AuthentikError


@pytest.fixture
def config():
    return AuthentikConfig(
        authentik_url="http://127.0.0.1:9000",
        authentik_token="test-token",
        authentik_public_key_url="/application/o/test/jwks/"
    )


@pytest.fixture
def mock_jwks_response():
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "test-key-1",
                "alg": "RS256",
                "n": "xGOr-H0A-6_BOXMq83kU00T5Fzv3OQbSS34aTUg13S7iCOUW",
                "e": "AQAB"
            },
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "test-key-2",
                "alg": "RS256",
                "n": "yGOr-H0A-6_BOXMq83kU00T5Fzv3OQbSS34aTUg13S7iCOUW",
                "e": "AQAB"
            }
        ]
    }


@pytest.mark.asyncio
class TestJWKSCache:
    
    async def test_initialization(self, config):
        cache = JWKSCache(config)
        assert cache.config == config
        assert not cache.is_cached
        assert cache._last_fetch_time is None
    
    async def test_context_manager(self, config):
        async with JWKSCache(config) as cache:
            assert cache is not None
            assert hasattr(cache, '_client')
    
    @patch('httpx.AsyncClient')
    async def test_fetch_keys_success(self, mock_client_class, config, mock_jwks_response):
        mock_client = AsyncMock()
        mock_client_class.return_value = mock_client
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = mock_jwks_response
        mock_client.get.return_value = mock_response
        
        cache = JWKSCache(config)
        cache._client = mock_client
        
        keys = await cache.get_keys()
        
        assert keys == mock_jwks_response
        assert cache.is_cached
        assert cache._last_fetch_time is not None
        
        # Verify the request was made correctly
        mock_client.get.assert_called_once_with(
            config.jwks_url,
            headers={
                "Accept": "application/json",
                "User-Agent": "nAI-Backend/1.0"
            }
        )
    
    @patch('httpx.AsyncClient')
    async def test_cache_hit(self, mock_client_class, config, mock_jwks_response):
        mock_client = AsyncMock()
        mock_client_class.return_value = mock_client
        
        cache = JWKSCache(config)
        cache._client = mock_client
        
        # Manually set cache
        cache._cache["jwks"] = mock_jwks_response
        
        # Get keys - should not make HTTP request
        keys = await cache.get_keys()
        
        assert keys == mock_jwks_response
        mock_client.get.assert_not_called()
    
    @patch('httpx.AsyncClient')
    async def test_http_error_handling(self, mock_client_class, config):
        mock_client = AsyncMock()
        mock_client_class.return_value = mock_client
        
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Not found"
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "404 Not Found",
            request=Mock(),
            response=mock_response
        )
        mock_client.get.return_value = mock_response
        
        cache = JWKSCache(config)
        cache._client = mock_client
        
        with pytest.raises(AuthentikError) as exc_info:
            await cache.get_keys()
        
        assert "Failed to fetch JWKS: HTTP 404" in str(exc_info.value)
    
    @patch('httpx.AsyncClient')
    async def test_invalid_jwks_structure(self, mock_client_class, config):
        mock_client = AsyncMock()
        mock_client_class.return_value = mock_client
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {"invalid": "structure"}
        mock_client.get.return_value = mock_response
        
        cache = JWKSCache(config)
        cache._client = mock_client
        
        with pytest.raises(AuthentikError) as exc_info:
            await cache.get_keys()
        
        assert "Invalid JWKS response structure" in str(exc_info.value)
    
    async def test_get_key_by_kid(self, config, mock_jwks_response):
        cache = JWKSCache(config)
        cache._cache["jwks"] = mock_jwks_response
        
        # Test finding existing key
        key = await cache.get_key_by_kid("test-key-1")
        assert key is not None
        assert key["kid"] == "test-key-1"
        
        # Test non-existent key
        key = await cache.get_key_by_kid("non-existent")
        assert key is None
    
    @patch('httpx.AsyncClient')
    async def test_refresh(self, mock_client_class, config, mock_jwks_response):
        mock_client = AsyncMock()
        mock_client_class.return_value = mock_client
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = mock_jwks_response
        mock_client.get.return_value = mock_response
        
        cache = JWKSCache(config)
        cache._client = mock_client
        
        # Set some initial cache
        cache._cache["jwks"] = {"old": "data"}
        cache._last_fetch_time = 12345
        
        # Refresh
        await cache.refresh()
        
        # Verify cache was cleared and refetched
        assert cache._cache["jwks"] == mock_jwks_response
        assert cache._last_fetch_time > 12345
        mock_client.get.assert_called_once()
    
    def test_clear(self, config):
        cache = JWKSCache(config)
        cache._cache["jwks"] = {"test": "data"}
        cache._last_fetch_time = 12345
        
        cache.clear()
        
        assert not cache.is_cached
        assert cache._last_fetch_time is None
    
    def test_cache_stats(self, config, mock_jwks_response):
        cache = JWKSCache(config)
        
        # Initial stats
        stats = cache.cache_stats
        assert stats["is_cached"] is False
        assert stats["cache_size"] == 0
        assert stats["last_fetch_time"] is None
        
        # After caching
        cache._cache["jwks"] = mock_jwks_response
        cache._last_fetch_time = datetime.now().timestamp()
        
        stats = cache.cache_stats
        assert stats["is_cached"] is True
        assert stats["cache_size"] == 1
        assert stats["last_fetch_time"] is not None
    
    @patch('httpx.AsyncClient')
    async def test_rate_limiting(self, mock_client_class, config, mock_jwks_response):
        mock_client = AsyncMock()
        mock_client_class.return_value = mock_client
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = mock_jwks_response
        mock_client.get.return_value = mock_response
        
        cache = JWKSCache(config)
        cache._client = mock_client
        cache._min_fetch_interval = 1  # 1 second for testing
        
        # First fetch
        await cache.get_keys()
        assert mock_client.get.call_count == 1
        
        # Clear cache to force refetch
        cache._cache.clear()
        
        # Try to fetch again immediately - should be rate limited
        result = await cache.get_keys()
        assert result == {"keys": []}
        assert mock_client.get.call_count == 1  # No additional call
        
        # Wait and try again
        await asyncio.sleep(1.1)
        cache._cache.clear()
        await cache.get_keys()
        assert mock_client.get.call_count == 2  # Now it should fetch