"""Challenge store for WebAuthn authentication."""

from redis.asyncio import Redis

from src.core.logging import get_logger

logger = get_logger(__name__)


class ChallengeStore:
    """Store and retrieve WebAuthn challenges using Redis."""

    def __init__(self, redis_client: Redis):
        """
        Initialize challenge store.
        
        Args:
            redis_client: Redis client instance
        """
        self.redis = redis_client
        self.ttl = 300  # 5 minutes TTL for challenges

    def _get_key(self, user_id: str, challenge_type: str) -> str:
        """
        Generate Redis key for challenge.
        
        Args:
            user_id: User identifier
            challenge_type: Type of challenge (registration/authentication)
            
        Returns:
            Redis key
        """
        return f"webauthn:challenge:{challenge_type}:{user_id}"

    async def store_challenge(
        self,
        user_id: str,
        challenge: str,
        challenge_type: str
    ) -> bool:
        """
        Store challenge in Redis.
        
        Args:
            user_id: User identifier
            challenge: Challenge value
            challenge_type: Type of challenge
            
        Returns:
            True if stored successfully
        """
        try:
            key = self._get_key(user_id, challenge_type)

            # Store with TTL
            await self.redis.setex(
                key,
                self.ttl,
                challenge
            )

            logger.debug(
                "Stored challenge",
                user_id=user_id,
                challenge_type=challenge_type,
                ttl=self.ttl
            )

            return True

        except Exception as e:
            logger.error(
                "Failed to store challenge",
                user_id=user_id,
                challenge_type=challenge_type,
                error=str(e),
                exc_info=True
            )
            # Don't fail the operation if Redis is down
            # In production, you might want to use a fallback
            return False

    async def retrieve_challenge(
        self,
        user_id: str,
        challenge_type: str
    ) -> str | None:
        """
        Retrieve and delete challenge from Redis.
        
        Args:
            user_id: User identifier
            challenge_type: Type of challenge
            
        Returns:
            Challenge value if found
        """
        try:
            key = self._get_key(user_id, challenge_type)

            # Get and delete atomically
            challenge = await self.redis.getdel(key)

            if challenge:
                logger.debug(
                    "Retrieved challenge",
                    user_id=user_id,
                    challenge_type=challenge_type
                )
                return challenge.decode('utf-8') if isinstance(challenge, bytes) else challenge
            else:
                logger.warning(
                    "Challenge not found",
                    user_id=user_id,
                    challenge_type=challenge_type
                )
                return None

        except Exception as e:
            logger.error(
                "Failed to retrieve challenge",
                user_id=user_id,
                challenge_type=challenge_type,
                error=str(e),
                exc_info=True
            )
            return None

    async def clear_user_challenges(self, user_id: str) -> int:
        """
        Clear all challenges for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Number of challenges cleared
        """
        try:
            # Find all challenge keys for user
            pattern = f"webauthn:challenge:*:{user_id}"
            keys = []

            # Use scan to find matching keys
            async for key in self.redis.scan_iter(match=pattern):
                keys.append(key)

            if keys:
                # Delete all found keys
                deleted = await self.redis.delete(*keys)

                logger.info(
                    "Cleared user challenges",
                    user_id=user_id,
                    count=deleted
                )

                return deleted
            else:
                return 0

        except Exception as e:
            logger.error(
                "Failed to clear user challenges",
                user_id=user_id,
                error=str(e),
                exc_info=True
            )
            return 0


class InMemoryChallengeStore(ChallengeStore):
    """
    In-memory challenge store for development/testing.
    
    This is a fallback when Redis is not available.
    NOT suitable for production use in multi-server environments.
    """

    def __init__(self):
        """Initialize in-memory store."""
        self.challenges = {}
        self.ttl = 300  # 5 minutes
        logger.warning("Using in-memory challenge store - not suitable for production!")

    async def store_challenge(
        self,
        user_id: str,
        challenge: str,
        challenge_type: str
    ) -> bool:
        """Store challenge in memory."""
        try:
            import time
            key = self._get_key(user_id, challenge_type)

            # Store with expiry time
            self.challenges[key] = {
                "challenge": challenge,
                "expires_at": time.time() + self.ttl
            }

            # Clean up expired entries
            await self._cleanup_expired()

            return True

        except Exception as e:
            logger.error(
                "Failed to store challenge in memory",
                error=str(e),
                exc_info=True
            )
            return False

    async def retrieve_challenge(
        self,
        user_id: str,
        challenge_type: str
    ) -> str | None:
        """Retrieve challenge from memory."""
        try:
            import time
            key = self._get_key(user_id, challenge_type)

            # Check if exists and not expired
            if key in self.challenges:
                entry = self.challenges[key]
                if entry["expires_at"] > time.time():
                    # Delete after retrieval
                    challenge = entry["challenge"]
                    del self.challenges[key]
                    return challenge
                else:
                    # Expired
                    del self.challenges[key]

            return None

        except Exception as e:
            logger.error(
                "Failed to retrieve challenge from memory",
                error=str(e),
                exc_info=True
            )
            return None

    async def clear_user_challenges(self, user_id: str) -> int:
        """Clear user challenges from memory."""
        try:
            pattern = f"webauthn:challenge:*:{user_id}"
            cleared = 0

            # Find and delete matching keys
            keys_to_delete = [
                key for key in self.challenges.keys()
                if key.endswith(f":{user_id}")
            ]

            for key in keys_to_delete:
                del self.challenges[key]
                cleared += 1

            return cleared

        except Exception as e:
            logger.error(
                "Failed to clear user challenges from memory",
                error=str(e),
                exc_info=True
            )
            return 0

    async def _cleanup_expired(self):
        """Clean up expired entries."""
        import time
        current_time = time.time()

        expired_keys = [
            key for key, entry in self.challenges.items()
            if entry["expires_at"] <= current_time
        ]

        for key in expired_keys:
            del self.challenges[key]
