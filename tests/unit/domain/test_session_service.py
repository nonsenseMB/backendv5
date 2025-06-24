"""
Unit tests for Domain Session Service.
Tests in-memory session management and lifecycle operations.
"""

from datetime import datetime, timedelta, UTC
from unittest.mock import patch
from uuid import uuid4, UUID

import pytest

from src.domain.auth.session_service import SessionInfo, SessionService


class TestSessionInfo:
    """Test SessionInfo class functionality."""

    def test_session_info_initialization_minimal(self):
        """Test SessionInfo initialization with minimal parameters."""
        session_id = uuid4()
        user_id = uuid4()
        tenant_id = uuid4()

        with patch('src.domain.auth.session_service.settings') as mock_settings:
            mock_settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS = 30

            session = SessionInfo(
                session_id=session_id,
                user_id=user_id,
                tenant_id=tenant_id
            )

            assert session.session_id == session_id
            assert session.user_id == user_id
            assert session.tenant_id == tenant_id
            assert session.external_session_id is None
            assert session.is_active is True
            assert isinstance(session.created_at, datetime)
            assert isinstance(session.expires_at, datetime)
            assert isinstance(session.last_activity, datetime)

    def test_session_info_initialization_with_external_session(self):
        """Test SessionInfo initialization with external session ID."""
        session_id = uuid4()
        user_id = uuid4()
        tenant_id = uuid4()
        external_session_id = "ext_session_123"

        with patch('src.domain.auth.session_service.settings') as mock_settings:
            mock_settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS = 30

            session = SessionInfo(
                session_id=session_id,
                user_id=user_id,
                tenant_id=tenant_id,
                external_session_id=external_session_id
            )

            assert session.external_session_id == external_session_id

    def test_session_info_initialization_with_custom_times(self):
        """Test SessionInfo initialization with custom created_at and expires_at."""
        session_id = uuid4()
        user_id = uuid4()
        tenant_id = uuid4()
        created_at = datetime.now(UTC) - timedelta(hours=1)
        expires_at = datetime.now(UTC) + timedelta(hours=12)

        session = SessionInfo(
            session_id=session_id,
            user_id=user_id,
            tenant_id=tenant_id,
            created_at=created_at,
            expires_at=expires_at
        )

        assert session.created_at == created_at
        assert session.expires_at == expires_at

    def test_session_info_default_expiration(self):
        """Test SessionInfo uses default expiration from settings."""
        session_id = uuid4()
        user_id = uuid4()
        tenant_id = uuid4()

        with patch('src.domain.auth.session_service.settings') as mock_settings:
            mock_settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS = 7

            session = SessionInfo(
                session_id=session_id,
                user_id=user_id,
                tenant_id=tenant_id
            )

            # Verify expiration is approximately 7 days from creation
            expected_expires = session.created_at + timedelta(days=7)
            time_diff = abs((session.expires_at - expected_expires).total_seconds())
            assert time_diff < 1  # Allow 1 second tolerance

    def test_session_info_timestamps_utc(self):
        """Test SessionInfo timestamps are in UTC."""
        session_id = uuid4()
        user_id = uuid4()
        tenant_id = uuid4()

        with patch('src.domain.auth.session_service.settings') as mock_settings:
            mock_settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS = 30

            session = SessionInfo(
                session_id=session_id,
                user_id=user_id,
                tenant_id=tenant_id
            )

            assert session.created_at.tzinfo == UTC
            assert session.expires_at.tzinfo == UTC
            assert session.last_activity.tzinfo == UTC


class TestSessionService:
    """Test SessionService functionality."""

    @pytest.fixture
    def session_service(self):
        """Create SessionService instance."""
        return SessionService()

    @pytest.fixture
    def test_user_id(self):
        """Test user ID."""
        return uuid4()

    @pytest.fixture
    def test_tenant_id(self):
        """Test tenant ID."""
        return uuid4()

    def test_session_service_initialization(self, session_service):
        """Test SessionService initialization."""
        assert isinstance(session_service._sessions, dict)
        assert len(session_service._sessions) == 0

    async def test_create_session_minimal(self, session_service, test_user_id, test_tenant_id):
        """Test session creation with minimal parameters."""
        session_id = await session_service.create_session(
            user_id=test_user_id,
            tenant_id=test_tenant_id
        )

        assert isinstance(session_id, UUID)
        assert session_id in session_service._sessions

        session_info = session_service._sessions[session_id]
        assert session_info.user_id == test_user_id
        assert session_info.tenant_id == test_tenant_id
        assert session_info.external_session_id is None
        assert session_info.is_active is True

    async def test_create_session_with_external_session_id(
        self, session_service, test_user_id, test_tenant_id
    ):
        """Test session creation with external session ID."""
        external_session_id = "ext_session_456"
        
        session_id = await session_service.create_session(
            user_id=test_user_id,
            tenant_id=test_tenant_id,
            external_session_id=external_session_id
        )

        session_info = session_service._sessions[session_id]
        assert session_info.external_session_id == external_session_id

    async def test_create_session_with_custom_created_at(
        self, session_service, test_user_id, test_tenant_id
    ):
        """Test session creation with custom created_at time."""
        created_at = datetime.now(UTC) - timedelta(hours=2)
        
        session_id = await session_service.create_session(
            user_id=test_user_id,
            tenant_id=test_tenant_id,
            created_at=created_at
        )

        session_info = session_service._sessions[session_id]
        assert session_info.created_at == created_at

    async def test_create_multiple_sessions(self, session_service, test_user_id, test_tenant_id):
        """Test creating multiple sessions."""
        session_ids = []
        
        for i in range(3):
            session_id = await session_service.create_session(
                user_id=test_user_id,
                tenant_id=test_tenant_id,
                external_session_id=f"ext_session_{i}"
            )
            session_ids.append(session_id)

        assert len(session_service._sessions) == 3
        assert all(sid in session_service._sessions for sid in session_ids)
        assert len(set(session_ids)) == 3  # All unique

    async def test_validate_session_success(self, session_service, test_user_id, test_tenant_id):
        """Test successful session validation."""
        session_id = await session_service.create_session(
            user_id=test_user_id,
            tenant_id=test_tenant_id
        )

        # Store original last activity
        original_activity = session_service._sessions[session_id].last_activity

        # Small delay to ensure time difference
        import asyncio
        await asyncio.sleep(0.01)

        result = await session_service.validate_session(session_id)

        assert result is True
        # Verify last activity was updated
        assert session_service._sessions[session_id].last_activity > original_activity

    async def test_validate_session_not_found(self, session_service):
        """Test validation of non-existent session."""
        non_existent_id = uuid4()
        
        result = await session_service.validate_session(non_existent_id)
        
        assert result is False

    async def test_validate_session_inactive(self, session_service, test_user_id, test_tenant_id):
        """Test validation of inactive session."""
        session_id = await session_service.create_session(
            user_id=test_user_id,
            tenant_id=test_tenant_id
        )

        # Mark session as inactive
        session_service._sessions[session_id].is_active = False

        result = await session_service.validate_session(session_id)
        
        assert result is False

    async def test_validate_session_expired(self, session_service, test_user_id, test_tenant_id):
        """Test validation of expired session."""
        # Create session with past expiration
        expired_time = datetime.now(UTC) - timedelta(hours=1)
        
        session_id = await session_service.create_session(
            user_id=test_user_id,
            tenant_id=test_tenant_id
        )

        # Manually set expiration to the past
        session_service._sessions[session_id].expires_at = expired_time

        result = await session_service.validate_session(session_id)
        
        assert result is False
        # Verify session was marked as inactive
        assert session_service._sessions[session_id].is_active is False

    async def test_get_session_valid(self, session_service, test_user_id, test_tenant_id):
        """Test getting valid session."""
        session_id = await session_service.create_session(
            user_id=test_user_id,
            tenant_id=test_tenant_id,
            external_session_id="test_external"
        )

        session_info = await session_service.get_session(session_id)

        assert session_info is not None
        assert session_info.session_id == session_id
        assert session_info.user_id == test_user_id
        assert session_info.tenant_id == test_tenant_id
        assert session_info.external_session_id == "test_external"

    async def test_get_session_invalid(self, session_service, test_user_id, test_tenant_id):
        """Test getting invalid session."""
        # Create expired session
        session_id = await session_service.create_session(
            user_id=test_user_id,
            tenant_id=test_tenant_id
        )

        # Expire the session
        session_service._sessions[session_id].expires_at = datetime.now(UTC) - timedelta(hours=1)

        session_info = await session_service.get_session(session_id)

        assert session_info is None

    async def test_get_session_not_found(self, session_service):
        """Test getting non-existent session."""
        non_existent_id = uuid4()
        
        session_info = await session_service.get_session(non_existent_id)
        
        assert session_info is None

    async def test_invalidate_session_success(self, session_service, test_user_id, test_tenant_id):
        """Test successful session invalidation."""
        session_id = await session_service.create_session(
            user_id=test_user_id,
            tenant_id=test_tenant_id
        )

        result = await session_service.invalidate_session(session_id)

        assert result is True
        assert session_service._sessions[session_id].is_active is False

    async def test_invalidate_session_not_found(self, session_service):
        """Test invalidation of non-existent session."""
        non_existent_id = uuid4()
        
        result = await session_service.invalidate_session(non_existent_id)
        
        assert result is False

    async def test_invalidate_user_sessions(self, session_service, test_user_id, test_tenant_id):
        """Test invalidating all sessions for a user."""
        # Create multiple sessions for the user
        user_sessions = []
        for i in range(3):
            session_id = await session_service.create_session(
                user_id=test_user_id,
                tenant_id=test_tenant_id,
                external_session_id=f"session_{i}"
            )
            user_sessions.append(session_id)

        # Create session for different user
        other_user_id = uuid4()
        other_session_id = await session_service.create_session(
            user_id=other_user_id,
            tenant_id=test_tenant_id
        )

        # Invalidate user sessions
        count = await session_service.invalidate_user_sessions(test_user_id)

        assert count == 3
        
        # Verify user sessions are inactive
        for session_id in user_sessions:
            assert session_service._sessions[session_id].is_active is False
        
        # Verify other user session is still active
        assert session_service._sessions[other_session_id].is_active is True

    async def test_invalidate_user_sessions_no_sessions(self, session_service):
        """Test invalidating sessions for user with no sessions."""
        non_existent_user = uuid4()
        
        count = await session_service.invalidate_user_sessions(non_existent_user)
        
        assert count == 0

    async def test_invalidate_user_sessions_already_inactive(
        self, session_service, test_user_id, test_tenant_id
    ):
        """Test invalidating sessions that are already inactive."""
        # Create session and invalidate it
        session_id = await session_service.create_session(
            user_id=test_user_id,
            tenant_id=test_tenant_id
        )
        await session_service.invalidate_session(session_id)

        # Try to invalidate again
        count = await session_service.invalidate_user_sessions(test_user_id)

        assert count == 0  # No active sessions to invalidate

    async def test_cleanup_expired_sessions(self, session_service, test_user_id, test_tenant_id):
        """Test cleanup of expired sessions."""
        # Create active session
        active_session_id = await session_service.create_session(
            user_id=test_user_id,
            tenant_id=test_tenant_id
        )

        # Create expired session
        expired_session_id = await session_service.create_session(
            user_id=test_user_id,
            tenant_id=test_tenant_id
        )
        session_service._sessions[expired_session_id].expires_at = datetime.now(UTC) - timedelta(hours=1)

        # Create inactive session
        inactive_session_id = await session_service.create_session(
            user_id=test_user_id,
            tenant_id=test_tenant_id
        )
        session_service._sessions[inactive_session_id].is_active = False

        initial_count = len(session_service._sessions)
        assert initial_count == 3

        # Cleanup expired sessions
        cleaned_count = await session_service.cleanup_expired_sessions()

        assert cleaned_count == 2  # Expired and inactive sessions
        assert len(session_service._sessions) == 1
        assert active_session_id in session_service._sessions
        assert expired_session_id not in session_service._sessions
        assert inactive_session_id not in session_service._sessions

    async def test_cleanup_expired_sessions_no_expired(self, session_service, test_user_id, test_tenant_id):
        """Test cleanup when no expired sessions exist."""
        # Create only active sessions
        for i in range(3):
            await session_service.create_session(
                user_id=test_user_id,
                tenant_id=test_tenant_id
            )

        initial_count = len(session_service._sessions)
        
        cleaned_count = await session_service.cleanup_expired_sessions()

        assert cleaned_count == 0
        assert len(session_service._sessions) == initial_count

    async def test_get_active_session_count_all(self, session_service, test_user_id, test_tenant_id):
        """Test getting count of all active sessions."""
        # Create active sessions
        for i in range(3):
            await session_service.create_session(
                user_id=test_user_id,
                tenant_id=test_tenant_id
            )

        # Create inactive session
        inactive_session_id = await session_service.create_session(
            user_id=test_user_id,
            tenant_id=test_tenant_id
        )
        session_service._sessions[inactive_session_id].is_active = False

        count = await session_service.get_active_session_count()

        assert count == 3  # Only active sessions

    async def test_get_active_session_count_for_user(self, session_service, test_user_id, test_tenant_id):
        """Test getting count of active sessions for specific user."""
        # Create sessions for test user
        for i in range(2):
            await session_service.create_session(
                user_id=test_user_id,
                tenant_id=test_tenant_id
            )

        # Create session for different user
        other_user_id = uuid4()
        await session_service.create_session(
            user_id=other_user_id,
            tenant_id=test_tenant_id
        )

        count = await session_service.get_active_session_count(test_user_id)

        assert count == 2  # Only sessions for test user

    async def test_get_active_session_count_no_sessions(self, session_service):
        """Test getting count when no sessions exist."""
        count = await session_service.get_active_session_count()
        
        assert count == 0

        # Test for specific user
        user_id = uuid4()
        count = await session_service.get_active_session_count(user_id)
        
        assert count == 0


class TestSessionServiceEdgeCases:
    """Test edge cases and complex scenarios."""

    @pytest.fixture
    def session_service(self):
        """Create SessionService instance."""
        return SessionService()

    async def test_concurrent_session_operations(self, session_service):
        """Test concurrent session operations."""
        user_id = uuid4()
        tenant_id = uuid4()

        # Create session
        session_id = await session_service.create_session(
            user_id=user_id,
            tenant_id=tenant_id
        )

        # Perform multiple operations on the same session
        validation_result = await session_service.validate_session(session_id)
        session_info = await session_service.get_session(session_id)
        invalidation_result = await session_service.invalidate_session(session_id)

        assert validation_result is True
        assert session_info is not None
        assert invalidation_result is True
        assert session_service._sessions[session_id].is_active is False

    async def test_session_lifecycle_complete(self, session_service):
        """Test complete session lifecycle."""
        user_id = uuid4()
        tenant_id = uuid4()

        # 1. Create session
        session_id = await session_service.create_session(
            user_id=user_id,
            tenant_id=tenant_id,
            external_session_id="lifecycle_test"
        )
        assert len(session_service._sessions) == 1

        # 2. Validate session
        assert await session_service.validate_session(session_id) is True

        # 3. Get session info
        session_info = await session_service.get_session(session_id)
        assert session_info is not None
        assert session_info.external_session_id == "lifecycle_test"

        # 4. Check active count
        count = await session_service.get_active_session_count(user_id)
        assert count == 1

        # 5. Invalidate session
        assert await session_service.invalidate_session(session_id) is True

        # 6. Verify session is inactive
        assert await session_service.validate_session(session_id) is False
        assert await session_service.get_session(session_id) is None

        # 7. Check active count again
        count = await session_service.get_active_session_count(user_id)
        assert count == 0

        # 8. Cleanup (should remove inactive session)
        cleaned = await session_service.cleanup_expired_sessions()
        assert cleaned == 1
        assert len(session_service._sessions) == 0

    async def test_multiple_users_sessions(self, session_service):
        """Test session management with multiple users."""
        users = [uuid4() for _ in range(3)]
        tenant_id = uuid4()

        # Create sessions for each user
        user_sessions = {}
        for user_id in users:
            user_sessions[user_id] = []
            for i in range(2):  # 2 sessions per user
                session_id = await session_service.create_session(
                    user_id=user_id,
                    tenant_id=tenant_id
                )
                user_sessions[user_id].append(session_id)

        # Verify total sessions
        total_count = await session_service.get_active_session_count()
        assert total_count == 6  # 3 users * 2 sessions

        # Verify per-user counts
        for user_id in users:
            user_count = await session_service.get_active_session_count(user_id)
            assert user_count == 2

        # Invalidate one user's sessions
        invalidated = await session_service.invalidate_user_sessions(users[0])
        assert invalidated == 2

        # Verify counts after invalidation
        total_count = await session_service.get_active_session_count()
        assert total_count == 4

        user_count = await session_service.get_active_session_count(users[0])
        assert user_count == 0

        # Cleanup inactive sessions
        cleaned = await session_service.cleanup_expired_sessions()
        assert cleaned == 2  # Only inactive sessions from users[0]

    async def test_session_expiration_boundary(self, session_service):
        """Test session expiration at exact boundary."""
        user_id = uuid4()
        tenant_id = uuid4()

        # Create session that expires very soon
        future_time = datetime.now(UTC) + timedelta(seconds=1)
        session_id = await session_service.create_session(
            user_id=user_id,
            tenant_id=tenant_id
        )
        
        # Set expiration to future time
        session_service._sessions[session_id].expires_at = future_time

        # Validate before expiration
        assert await session_service.validate_session(session_id) is True

        # Wait for expiration
        import asyncio
        await asyncio.sleep(1.1)

        # Validate after expiration
        assert await session_service.validate_session(session_id) is False
        assert session_service._sessions[session_id].is_active is False

    async def test_session_info_immutability_after_invalidation(self, session_service):
        """Test session info remains accessible after invalidation."""
        user_id = uuid4()
        tenant_id = uuid4()
        external_session_id = "test_external"

        session_id = await session_service.create_session(
            user_id=user_id,
            tenant_id=tenant_id,
            external_session_id=external_session_id
        )

        # Get original session info
        original_info = session_service._sessions[session_id]
        assert original_info.is_active is True

        # Invalidate session
        await session_service.invalidate_session(session_id)

        # Verify session info is still accessible but marked inactive
        assert session_service._sessions[session_id] is original_info
        assert session_service._sessions[session_id].is_active is False
        assert session_service._sessions[session_id].external_session_id == external_session_id