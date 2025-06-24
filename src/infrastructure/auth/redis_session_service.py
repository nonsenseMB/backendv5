"""Redis-based session service for managing user sessions."""
from datetime import UTC, datetime, timedelta
from typing import Optional
from uuid import UUID, uuid4

from src.core.config import settings
from src.core.logging import get_logger
from src.domain.auth.session_service import SessionInfo, SessionService
from src.infrastructure.cache import RedisClient, get_redis_client

logger = get_logger(__name__)


class RedisSessionService(SessionService):
    """Redis-backed session management service."""

    def __init__(self, redis_client: Optional[RedisClient] = None):
        self.redis: Optional[RedisClient] = redis_client
        self._initialized = False
        self._fallback_sessions = {}  # In-memory fallback when Redis is not available

    async def _ensure_redis(self) -> Optional[RedisClient]:
        """Ensure Redis client is available."""
        if not self.redis:
            try:
                self.redis = await get_redis_client()
            except Exception as e:
                logger.warning(f"Redis not available: {e}. Using in-memory fallback.")
                return None
        if not self._initialized:
            logger.info("Redis session service initialized")
            self._initialized = True
        return self.redis

    def _session_key(self, session_id: UUID) -> str:
        """Generate Redis key for session."""
        return f"session:{session_id}"

    def _user_sessions_pattern(self, user_id: UUID) -> str:
        """Generate Redis pattern for user's sessions."""
        return f"user_sessions:{user_id}:*"

    async def create_session(
        self,
        user_id: UUID,
        tenant_id: UUID,
        external_session_id: Optional[str] = None,
        created_at: Optional[datetime] = None,
    ) -> UUID:
        """Create a new session in Redis."""
        redis = await self._ensure_redis()
        session_id = uuid4()
        
        session = SessionInfo(
            session_id=session_id,
            user_id=user_id,
            tenant_id=tenant_id,
            external_session_id=external_session_id,
            created_at=created_at,
        )

        # Store session data
        session_data = {
            "session_id": str(session_id),
            "user_id": str(user_id),
            "tenant_id": str(tenant_id),
            "external_session_id": external_session_id,
            "created_at": session.created_at.isoformat(),
            "expires_at": session.expires_at.isoformat(),
            "last_activity": session.last_activity.isoformat(),
            "is_active": session.is_active,
        }

        # Calculate TTL in seconds
        ttl = int((session.expires_at - datetime.now(UTC)).total_seconds())
        
        if redis:
            # Store in Redis with expiration
            await redis.set_json(
                self._session_key(session_id),
                session_data,
                expire=ttl
            )

            # Also store reference for user's sessions
            user_session_key = f"user_sessions:{user_id}:{session_id}"
            await redis.set(user_session_key, str(session_id), expire=ttl)
        else:
            # Use in-memory fallback
            self._fallback_sessions[str(session_id)] = session_data

        logger.info(
            "Session created" + (" in Redis" if redis else " in memory"),
            session_id=str(session_id),
            user_id=str(user_id),
            tenant_id=str(tenant_id),
            ttl_seconds=ttl,
        )

        return session_id

    async def validate_session(self, session_id: UUID) -> bool:
        """Validate if a session is still active in Redis."""
        redis = await self._ensure_redis()
        
        if redis:
            session_data = await redis.get_json(self._session_key(session_id))
        else:
            session_data = self._fallback_sessions.get(str(session_id))
        
        if not session_data:
            logger.debug("Session not found in Redis", session_id=str(session_id))
            return False

        if not session_data.get("is_active", False):
            logger.debug("Session inactive", session_id=str(session_id))
            return False

        # Update last activity
        session_data["last_activity"] = datetime.now(UTC).isoformat()
        
        # Recalculate TTL
        expires_at = datetime.fromisoformat(session_data["expires_at"])
        ttl = int((expires_at - datetime.now(UTC)).total_seconds())
        
        if ttl <= 0:
            logger.debug("Session expired", session_id=str(session_id))
            return False

        # Update session in Redis
        if redis:
            await redis.set_json(
                self._session_key(session_id),
                session_data,
                expire=ttl
            )
        else:
            self._fallback_sessions[str(session_id)] = session_data

        return True

    async def get_session(self, session_id: UUID) -> Optional[SessionInfo]:
        """Get session information from Redis."""
        redis = await self._ensure_redis()
        
        if not await self.validate_session(session_id):
            return None

        if redis:
            session_data = await redis.get_json(self._session_key(session_id))
        else:
            session_data = self._fallback_sessions.get(str(session_id))
        
        if not session_data:
            return None

        # Reconstruct SessionInfo
        session = SessionInfo(
            session_id=UUID(session_data["session_id"]),
            user_id=UUID(session_data["user_id"]),
            tenant_id=UUID(session_data["tenant_id"]),
            external_session_id=session_data.get("external_session_id"),
            created_at=datetime.fromisoformat(session_data["created_at"]),
            expires_at=datetime.fromisoformat(session_data["expires_at"]),
        )
        session.last_activity = datetime.fromisoformat(session_data["last_activity"])
        session.is_active = session_data["is_active"]

        return session

    async def invalidate_session(self, session_id: UUID) -> bool:
        """Invalidate a session in Redis."""
        redis = await self._ensure_redis()
        
        session_data = await redis.get_json(self._session_key(session_id))
        
        if session_data:
            # Mark as inactive but don't delete immediately
            session_data["is_active"] = False
            
            # Keep for audit trail (expire in 1 hour)
            await redis.set_json(
                self._session_key(session_id),
                session_data,
                expire=3600
            )
            
            # Remove user session reference
            user_id = session_data["user_id"]
            user_session_key = f"user_sessions:{user_id}:{session_id}"
            await redis.delete(user_session_key)
            
            logger.info(
                "Session invalidated in Redis",
                session_id=str(session_id),
                user_id=user_id,
            )
            return True

        return False

    async def invalidate_user_sessions(self, user_id: UUID) -> int:
        """Invalidate all sessions for a user."""
        redis = await self._ensure_redis()
        count = 0

        # Find all user's session references
        pattern = self._user_sessions_pattern(user_id)
        user_session_keys = await redis.keys(pattern)

        for key in user_session_keys:
            # Extract session_id from key
            session_id_str = await redis.get(key)
            if session_id_str:
                session_id = UUID(session_id_str)
                if await self.invalidate_session(session_id):
                    count += 1

        if count > 0:
            logger.info(
                "User sessions invalidated in Redis",
                user_id=str(user_id),
                session_count=count,
            )

        return count

    async def cleanup_expired_sessions(self) -> int:
        """Cleanup expired sessions from Redis."""
        # Redis automatically removes expired keys, so this is mainly for logging
        redis = await self._ensure_redis()
        
        # Count active sessions before cleanup
        pattern = "session:*"
        session_keys = await redis.keys(pattern)
        initial_count = len(session_keys)
        
        # Force check expiration by accessing each key
        expired_count = 0
        for key in session_keys:
            exists = await redis.exists(key)
            if not exists:
                expired_count += 1

        if expired_count > 0:
            logger.info(
                "Expired sessions detected",
                initial_count=initial_count,
                expired_count=expired_count,
                remaining_count=initial_count - expired_count,
            )

        return expired_count

    async def get_active_session_count(self, user_id: Optional[UUID] = None) -> int:
        """Get count of active sessions."""
        redis = await self._ensure_redis()
        
        if user_id:
            # Count user's active sessions
            pattern = self._user_sessions_pattern(user_id)
            user_session_keys = await redis.keys(pattern)
            
            count = 0
            for key in user_session_keys:
                session_id_str = await redis.get(key)
                if session_id_str:
                    session_id = UUID(session_id_str)
                    if await self.validate_session(session_id):
                        count += 1
            
            return count
        else:
            # Count all active sessions
            pattern = "session:*"
            session_keys = await redis.keys(pattern)
            
            count = 0
            for key in session_keys:
                session_data = await redis.get_json(key)
                if session_data and session_data.get("is_active", False):
                    count += 1
            
            return count