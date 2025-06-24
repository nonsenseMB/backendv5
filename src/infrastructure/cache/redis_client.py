"""Redis client for caching and session management."""
import json

import redis.asyncio as redis
from redis.asyncio import ConnectionPool

from src.core.config import settings
from src.core.logging import get_logger

logger = get_logger(__name__)


class RedisClient:
    """Async Redis client wrapper with connection pooling."""

    def __init__(self, redis_url: str = None):
        self.redis_url = redis_url or settings.REDIS_URL
        self._pool: ConnectionPool | None = None
        self._client: redis.Redis | None = None

    async def connect(self) -> None:
        """Initialize Redis connection pool."""
        if not self._pool:
            self._pool = ConnectionPool.from_url(
                self.redis_url,
                decode_responses=True,
                max_connections=settings.REDIS_POOL_SIZE
            )
            self._client = redis.Redis(connection_pool=self._pool)

            # Test connection
            await self._client.ping()
            logger.info("Redis connection established", url=self.redis_url)

    async def disconnect(self) -> None:
        """Close Redis connection pool."""
        if self._client:
            await self._client.close()
            self._client = None
        if self._pool:
            await self._pool.disconnect()
            self._pool = None
            logger.info("Redis connection closed")

    @property
    def client(self) -> redis.Redis:
        """Get Redis client instance."""
        if not self._client:
            raise RuntimeError("Redis client not connected. Call connect() first.")
        return self._client

    async def get(self, key: str) -> str | None:
        """Get value by key."""
        return await self.client.get(key)

    async def set(
        self,
        key: str,
        value: str,
        expire: int | None = None
    ) -> bool:
        """Set key-value pair with optional expiration (in seconds)."""
        return await self.client.set(key, value, ex=expire)

    async def delete(self, key: str) -> int:
        """Delete key."""
        return await self.client.delete(key)

    async def exists(self, key: str) -> bool:
        """Check if key exists."""
        return bool(await self.client.exists(key))

    async def expire(self, key: str, seconds: int) -> bool:
        """Set expiration on key."""
        return await self.client.expire(key, seconds)

    async def ttl(self, key: str) -> int:
        """Get time-to-live for key in seconds."""
        return await self.client.ttl(key)

    # JSON helpers
    async def get_json(self, key: str) -> dict | None:
        """Get JSON value by key."""
        value = await self.get(key)
        if value:
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                logger.error("Failed to decode JSON", key=key, value=value)
        return None

    async def set_json(
        self,
        key: str,
        value: dict,
        expire: int | None = None
    ) -> bool:
        """Set JSON value with optional expiration."""
        json_str = json.dumps(value)
        return await self.set(key, json_str, expire)

    # Pattern operations
    async def keys(self, pattern: str) -> list[str]:
        """Get all keys matching pattern."""
        return await self.client.keys(pattern)

    async def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching pattern."""
        keys = await self.keys(pattern)
        if keys:
            return await self.client.delete(*keys)
        return 0


# Singleton instance
_redis_client: RedisClient | None = None


async def get_redis_client() -> RedisClient:
    """Get singleton Redis client instance."""
    global _redis_client
    if _redis_client is None:
        _redis_client = RedisClient()
        await _redis_client.connect()
    return _redis_client
