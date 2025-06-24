"""Session service for managing user sessions."""
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from src.core.config import settings
from src.core.logging import get_logger

logger = get_logger(__name__)


class SessionInfo:
    """In-memory session information."""

    def __init__(
        self,
        session_id: UUID,
        user_id: UUID,
        tenant_id: UUID,
        external_session_id: str | None = None,
        created_at: datetime | None = None,
        expires_at: datetime | None = None,
    ):
        self.session_id = session_id
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.external_session_id = external_session_id
        self.created_at = created_at or datetime.now(UTC)
        self.expires_at = expires_at or (
            datetime.now(UTC) + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
        )
        self.last_activity = datetime.now(UTC)
        self.is_active = True


class SessionService:
    """Service for session management."""

    def __init__(self):
        # In-memory session storage (should be Redis in production)
        self._sessions: dict[UUID, SessionInfo] = {}
        logger.info("Session service initialized with in-memory storage")

    async def create_session(
        self,
        user_id: UUID,
        tenant_id: UUID,
        external_session_id: str | None = None,
        created_at: datetime | None = None,
    ) -> UUID:
        """Create a new session."""
        session_id = uuid4()

        session = SessionInfo(
            session_id=session_id,
            user_id=user_id,
            tenant_id=tenant_id,
            external_session_id=external_session_id,
            created_at=created_at,
        )

        self._sessions[session_id] = session

        logger.info(
            "Session created",
            session_id=str(session_id),
            user_id=str(user_id),
            tenant_id=str(tenant_id),
            external_session_id=external_session_id,
        )

        return session_id

    async def validate_session(self, session_id: UUID) -> bool:
        """Validate if a session is still active."""
        session = self._sessions.get(session_id)

        if not session:
            logger.debug("Session not found", session_id=str(session_id))
            return False

        if not session.is_active:
            logger.debug("Session inactive", session_id=str(session_id))
            return False

        if datetime.now(UTC) > session.expires_at:
            logger.debug("Session expired", session_id=str(session_id))
            session.is_active = False
            return False

        # Update last activity
        session.last_activity = datetime.now(UTC)

        return True

    async def get_session(self, session_id: UUID) -> SessionInfo | None:
        """Get session information."""
        session = self._sessions.get(session_id)

        if session and await self.validate_session(session_id):
            return session

        return None

    async def invalidate_session(self, session_id: UUID) -> bool:
        """Invalidate a session."""
        session = self._sessions.get(session_id)

        if session:
            session.is_active = False
            logger.info(
                "Session invalidated",
                session_id=str(session_id),
                user_id=str(session.user_id),
            )
            return True

        return False

    async def invalidate_user_sessions(self, user_id: UUID) -> int:
        """Invalidate all sessions for a user."""
        count = 0

        for session in self._sessions.values():
            if session.user_id == user_id and session.is_active:
                session.is_active = False
                count += 1

        if count > 0:
            logger.info(
                "User sessions invalidated",
                user_id=str(user_id),
                session_count=count,
            )

        return count

    async def cleanup_expired_sessions(self) -> int:
        """Remove expired sessions from memory."""
        now = datetime.now(UTC)
        expired_sessions = []

        for session_id, session in self._sessions.items():
            if now > session.expires_at or not session.is_active:
                expired_sessions.append(session_id)

        for session_id in expired_sessions:
            del self._sessions[session_id]

        if expired_sessions:
            logger.info(
                "Expired sessions cleaned up",
                count=len(expired_sessions),
            )

        return len(expired_sessions)

    async def get_active_session_count(self, user_id: UUID | None = None) -> int:
        """Get count of active sessions."""
        count = 0

        for session in self._sessions.values():
            if session.is_active and (user_id is None or session.user_id == user_id):
                count += 1

        return count
