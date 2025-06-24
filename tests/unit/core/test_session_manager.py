"""
Unit tests for Session Manager.
Tests session lifecycle, validation, and security monitoring.
"""

import hashlib
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch
from uuid import uuid4, UUID

import pytest
from sqlalchemy.orm import Session

from src.core.auth.session_manager import (
    SessionManager,
    SessionError,
    SessionNotFoundError,
    SessionExpiredError
)
from src.infrastructure.database.models.auth import User
from src.infrastructure.database.models.tenant import Tenant
from src.infrastructure.database.models.user_session import UserSession, SessionActivity, SessionSecurityEvent


class TestSessionManager:
    """Test SessionManager functionality."""

    @pytest.fixture
    def mock_db(self):
        """Create mock database session."""
        return Mock(spec=Session)

    @pytest.fixture
    def session_manager(self, mock_db):
        """Create SessionManager instance."""
        return SessionManager(mock_db, timedelta(hours=24))

    @pytest.fixture
    def test_user_id(self):
        """Test user ID."""
        return uuid4()

    @pytest.fixture
    def test_tenant_id(self):
        """Test tenant ID."""
        return uuid4()

    @pytest.fixture
    def test_session_id(self):
        """Test session ID."""
        return uuid4()

    @pytest.fixture
    def mock_user(self, test_user_id):
        """Mock user object."""
        user = Mock(spec=User)
        user.id = test_user_id
        user.is_active = True
        return user

    @pytest.fixture
    def mock_tenant(self, test_tenant_id):
        """Mock tenant object."""
        tenant = Mock(spec=Tenant)
        tenant.id = test_tenant_id
        tenant.is_active = True
        return tenant

    @pytest.fixture
    def mock_session(self, test_session_id, test_user_id, test_tenant_id):
        """Mock session object."""
        session = Mock(spec=UserSession)
        session.id = test_session_id
        session.user_id = test_user_id
        session.tenant_id = test_tenant_id
        session.is_active = True
        session.created_at = datetime.utcnow()
        session.expires_at = datetime.utcnow() + timedelta(hours=24)
        session.last_activity = datetime.utcnow()
        session.is_expired.return_value = False
        session.update_activity = Mock()
        session.terminate = Mock()
        return session

    def test_init(self, mock_db):
        """Test SessionManager initialization."""
        manager = SessionManager(mock_db, timedelta(hours=12))
        
        assert manager.db == mock_db
        assert manager.default_session_duration == timedelta(hours=12)

    def test_init_default_duration(self, mock_db):
        """Test SessionManager initialization with default duration."""
        manager = SessionManager(mock_db)
        
        assert manager.default_session_duration == timedelta(hours=24)


class TestSessionCreation:
    """Test session creation functionality."""

    @pytest.fixture
    def session_manager(self, mock_db):
        """Create SessionManager instance."""
        return SessionManager(mock_db, timedelta(hours=24))

    @pytest.fixture
    def setup_valid_user_tenant(self, mock_db, mock_user, mock_tenant):
        """Setup valid user and tenant queries."""
        def query_side_effect(model):
            query_mock = Mock()
            if model == User:
                query_mock.filter.return_value.first.return_value = mock_user
            elif model == Tenant:
                query_mock.filter.return_value.first.return_value = mock_tenant
            return query_mock
        
        mock_db.query.side_effect = query_side_effect
        return mock_db

    async def test_create_session_success(
        self, session_manager, setup_valid_user_tenant, test_user_id, test_tenant_id
    ):
        """Test successful session creation."""
        # Setup
        mock_db = setup_valid_user_tenant
        created_session = Mock(spec=UserSession)
        created_session.id = uuid4()
        
        mock_db.add = Mock()
        mock_db.commit = Mock()
        mock_db.refresh = Mock(side_effect=lambda x: setattr(x, 'id', created_session.id))

        with patch.object(session_manager, '_log_session_activity', new_callable=AsyncMock) as mock_log, \
             patch.object(session_manager, '_check_concurrent_sessions', new_callable=AsyncMock) as mock_check:

            # Execute
            result = await session_manager.create_session(
                user_id=test_user_id,
                tenant_id=test_tenant_id,
                ip_address="192.168.1.1",
                user_agent="Mozilla/5.0 Test Browser",
                session_type="web",
                login_method="sso"
            )

            # Verify
            mock_db.add.assert_called_once()
            mock_db.commit.assert_called_once()
            mock_db.refresh.assert_called_once()
            mock_log.assert_called_once()
            mock_check.assert_called_once()

    async def test_create_session_with_custom_duration(
        self, session_manager, setup_valid_user_tenant, test_user_id, test_tenant_id
    ):
        """Test session creation with custom duration."""
        mock_db = setup_valid_user_tenant
        mock_db.add = Mock()
        mock_db.commit = Mock()
        mock_db.refresh = Mock()

        custom_duration = timedelta(hours=2)

        with patch.object(session_manager, '_log_session_activity', new_callable=AsyncMock), \
             patch.object(session_manager, '_check_concurrent_sessions', new_callable=AsyncMock), \
             patch('src.core.auth.session_manager.UserSession') as mock_session_class:

            await session_manager.create_session(
                user_id=test_user_id,
                tenant_id=test_tenant_id,
                session_duration=custom_duration
            )

            # Verify UserSession was created with correct expiration
            args, kwargs = mock_session_class.call_args
            expires_at = kwargs['expires_at']
            expected_expires = datetime.utcnow() + custom_duration
            
            # Allow 1 second tolerance for execution time
            assert abs((expires_at - expected_expires).total_seconds()) < 1

    async def test_create_session_ip_hashing(
        self, session_manager, setup_valid_user_tenant, test_user_id, test_tenant_id
    ):
        """Test IP address hashing during session creation."""
        mock_db = setup_valid_user_tenant
        mock_db.add = Mock()
        mock_db.commit = Mock()
        mock_db.refresh = Mock()

        ip_address = "192.168.1.100"
        expected_hash = hashlib.sha256(ip_address.encode()).hexdigest()

        with patch.object(session_manager, '_log_session_activity', new_callable=AsyncMock), \
             patch.object(session_manager, '_check_concurrent_sessions', new_callable=AsyncMock), \
             patch('src.core.auth.session_manager.UserSession') as mock_session_class:

            await session_manager.create_session(
                user_id=test_user_id,
                tenant_id=test_tenant_id,
                ip_address=ip_address
            )

            # Verify IP was hashed
            args, kwargs = mock_session_class.call_args
            assert kwargs['ip_address_hash'] == expected_hash

    async def test_create_session_no_ip_address(
        self, session_manager, setup_valid_user_tenant, test_user_id, test_tenant_id
    ):
        """Test session creation without IP address."""
        mock_db = setup_valid_user_tenant
        mock_db.add = Mock()
        mock_db.commit = Mock()
        mock_db.refresh = Mock()

        with patch.object(session_manager, '_log_session_activity', new_callable=AsyncMock), \
             patch.object(session_manager, '_check_concurrent_sessions', new_callable=AsyncMock), \
             patch('src.core.auth.session_manager.UserSession') as mock_session_class:

            await session_manager.create_session(
                user_id=test_user_id,
                tenant_id=test_tenant_id
            )

            # Verify IP hash is None
            args, kwargs = mock_session_class.call_args
            assert kwargs['ip_address_hash'] is None

    async def test_create_session_invalid_user(
        self, session_manager, mock_db, test_user_id, test_tenant_id
    ):
        """Test session creation with invalid user."""
        # Setup - no user found
        query_mock = Mock()
        query_mock.filter.return_value.first.return_value = None
        mock_db.query.return_value = query_mock

        with pytest.raises(SessionError, match="User .* not found or inactive"):
            await session_manager.create_session(
                user_id=test_user_id,
                tenant_id=test_tenant_id
            )

        mock_db.rollback.assert_called_once()

    async def test_create_session_inactive_user(
        self, session_manager, mock_db, test_user_id, test_tenant_id
    ):
        """Test session creation with inactive user."""
        # Setup - inactive user
        inactive_user = Mock(spec=User)
        inactive_user.is_active = False
        
        query_mock = Mock()
        query_mock.filter.return_value.first.return_value = inactive_user
        mock_db.query.return_value = query_mock

        with pytest.raises(SessionError, match="User .* not found or inactive"):
            await session_manager.create_session(
                user_id=test_user_id,
                tenant_id=test_tenant_id
            )

    async def test_create_session_invalid_tenant(
        self, session_manager, mock_db, mock_user, test_user_id, test_tenant_id
    ):
        """Test session creation with invalid tenant."""
        # Setup - valid user, no tenant
        def query_side_effect(model):
            query_mock = Mock()
            if model == User:
                query_mock.filter.return_value.first.return_value = mock_user
            elif model == Tenant:
                query_mock.filter.return_value.first.return_value = None
            return query_mock
        
        mock_db.query.side_effect = query_side_effect

        with pytest.raises(SessionError, match="Tenant .* not found or inactive"):
            await session_manager.create_session(
                user_id=test_user_id,
                tenant_id=test_tenant_id
            )

    async def test_create_session_with_device_id(
        self, session_manager, setup_valid_user_tenant, test_user_id, test_tenant_id
    ):
        """Test session creation with device ID."""
        mock_db = setup_valid_user_tenant
        mock_db.add = Mock()
        mock_db.commit = Mock()
        mock_db.refresh = Mock()

        device_id = uuid4()

        with patch.object(session_manager, '_log_session_activity', new_callable=AsyncMock), \
             patch.object(session_manager, '_check_concurrent_sessions', new_callable=AsyncMock), \
             patch('src.core.auth.session_manager.UserSession') as mock_session_class:

            await session_manager.create_session(
                user_id=test_user_id,
                tenant_id=test_tenant_id,
                device_id=device_id
            )

            args, kwargs = mock_session_class.call_args
            assert kwargs['device_id'] == device_id

    async def test_create_session_with_client_info(
        self, session_manager, setup_valid_user_tenant, test_user_id, test_tenant_id
    ):
        """Test session creation with client info."""
        mock_db = setup_valid_user_tenant
        mock_db.add = Mock()
        mock_db.commit = Mock()
        mock_db.refresh = Mock()

        client_info = {"browser": "Chrome", "version": "91.0"}

        with patch.object(session_manager, '_log_session_activity', new_callable=AsyncMock), \
             patch.object(session_manager, '_check_concurrent_sessions', new_callable=AsyncMock), \
             patch('src.core.auth.session_manager.UserSession') as mock_session_class:

            await session_manager.create_session(
                user_id=test_user_id,
                tenant_id=test_tenant_id,
                client_info=client_info
            )

            args, kwargs = mock_session_class.call_args
            assert kwargs['client_info'] == client_info

    async def test_create_session_database_error(
        self, session_manager, setup_valid_user_tenant, test_user_id, test_tenant_id
    ):
        """Test session creation with database error."""
        mock_db = setup_valid_user_tenant
        mock_db.add = Mock()
        mock_db.commit = Mock(side_effect=Exception("Database error"))

        with pytest.raises(SessionError, match="Session creation failed"):
            await session_manager.create_session(
                user_id=test_user_id,
                tenant_id=test_tenant_id
            )

        mock_db.rollback.assert_called_once()


class TestSessionValidation:
    """Test session validation functionality."""

    @pytest.fixture
    def session_manager(self, mock_db):
        """Create SessionManager instance."""
        return SessionManager(mock_db)

    async def test_validate_session_success(self, session_manager, mock_db, mock_session, test_session_id):
        """Test successful session validation."""
        mock_db.query.return_value.filter.return_value.first.return_value = mock_session

        result = await session_manager.validate_session(test_session_id)

        assert result == mock_session
        mock_session.update_activity.assert_called_once()
        mock_db.commit.assert_called_once()

    async def test_validate_session_without_activity_update(
        self, session_manager, mock_db, mock_session, test_session_id
    ):
        """Test session validation without activity update."""
        mock_db.query.return_value.filter.return_value.first.return_value = mock_session

        result = await session_manager.validate_session(test_session_id, update_activity=False)

        assert result == mock_session
        mock_session.update_activity.assert_not_called()
        mock_db.commit.assert_not_called()

    async def test_validate_session_not_found(self, session_manager, mock_db, test_session_id):
        """Test validation of non-existent session."""
        mock_db.query.return_value.filter.return_value.first.return_value = None

        with pytest.raises(SessionNotFoundError, match="Session .* not found"):
            await session_manager.validate_session(test_session_id)

    async def test_validate_session_inactive(self, session_manager, mock_db, mock_session, test_session_id):
        """Test validation of inactive session."""
        mock_session.is_active = False
        mock_db.query.return_value.filter.return_value.first.return_value = mock_session

        with pytest.raises(SessionNotFoundError, match="Session .* is inactive"):
            await session_manager.validate_session(test_session_id)

    async def test_validate_session_expired(self, session_manager, mock_db, mock_session, test_session_id):
        """Test validation of expired session."""
        mock_session.is_expired.return_value = True
        mock_db.query.return_value.filter.return_value.first.return_value = mock_session

        with patch.object(session_manager, '_log_session_activity', new_callable=AsyncMock) as mock_log:
            with pytest.raises(SessionExpiredError, match="Session .* has expired"):
                await session_manager.validate_session(test_session_id)

            mock_session.terminate.assert_called_once_with("expired")
            mock_db.commit.assert_called_once()
            mock_log.assert_called_once()

    async def test_validate_session_database_error(self, session_manager, mock_db, test_session_id):
        """Test session validation with database error."""
        mock_db.query.side_effect = Exception("Database error")

        with pytest.raises(SessionError, match="Session validation failed"):
            await session_manager.validate_session(test_session_id)


class TestUserSessions:
    """Test user session retrieval functionality."""

    @pytest.fixture
    def session_manager(self, mock_db):
        """Create SessionManager instance."""
        return SessionManager(mock_db)

    async def test_get_user_sessions_active_only(self, session_manager, mock_db, test_user_id):
        """Test getting active user sessions only."""
        mock_sessions = [Mock(spec=UserSession) for _ in range(3)]
        
        query_mock = Mock()
        query_mock.filter.return_value = query_mock
        query_mock.order_by.return_value.all.return_value = mock_sessions
        mock_db.query.return_value = query_mock

        result = await session_manager.get_user_sessions(test_user_id, active_only=True)

        assert result == mock_sessions
        # Verify filtering was applied
        assert query_mock.filter.call_count >= 2  # User filter + active filter

    async def test_get_user_sessions_all(self, session_manager, mock_db, test_user_id):
        """Test getting all user sessions."""
        mock_sessions = [Mock(spec=UserSession) for _ in range(5)]
        
        query_mock = Mock()
        query_mock.filter.return_value = query_mock
        query_mock.order_by.return_value.all.return_value = mock_sessions
        mock_db.query.return_value = query_mock

        result = await session_manager.get_user_sessions(test_user_id, active_only=False)

        assert result == mock_sessions
        # Only user filter should be applied
        assert query_mock.filter.call_count == 1

    async def test_get_user_sessions_exclude_current(self, session_manager, mock_db, test_user_id):
        """Test getting user sessions excluding current session."""
        current_session_id = uuid4()
        mock_sessions = [Mock(spec=UserSession) for _ in range(2)]
        
        query_mock = Mock()
        query_mock.filter.return_value = query_mock
        query_mock.order_by.return_value.all.return_value = mock_sessions
        mock_db.query.return_value = query_mock

        result = await session_manager.get_user_sessions(
            test_user_id,
            include_current=False,
            current_session_id=current_session_id
        )

        assert result == mock_sessions
        # User filter + active filter + exclude current = 3 filters
        assert query_mock.filter.call_count == 3

    async def test_get_user_sessions_empty_result(self, session_manager, mock_db, test_user_id):
        """Test getting user sessions with empty result."""
        query_mock = Mock()
        query_mock.filter.return_value = query_mock
        query_mock.order_by.return_value.all.return_value = []
        mock_db.query.return_value = query_mock

        result = await session_manager.get_user_sessions(test_user_id)

        assert result == []

    async def test_get_user_sessions_database_error(self, session_manager, mock_db, test_user_id):
        """Test getting user sessions with database error."""
        mock_db.query.side_effect = Exception("Database error")

        with pytest.raises(SessionError, match="Failed to get user sessions"):
            await session_manager.get_user_sessions(test_user_id)


class TestSessionTermination:
    """Test session termination functionality."""

    @pytest.fixture
    def session_manager(self, mock_db):
        """Create SessionManager instance."""
        return SessionManager(mock_db)

    async def test_terminate_session_success(self, session_manager, mock_db, mock_session, test_session_id):
        """Test successful session termination."""
        mock_db.query.return_value.filter.return_value.first.return_value = mock_session

        with patch.object(session_manager, '_log_session_activity', new_callable=AsyncMock) as mock_log:
            result = await session_manager.terminate_session(test_session_id, reason="logout")

            assert result is True
            mock_session.terminate.assert_called_once_with("logout")
            mock_db.commit.assert_called_once()
            mock_log.assert_called_once()

    async def test_terminate_session_not_found(self, session_manager, mock_db, test_session_id):
        """Test termination of non-existent session."""
        mock_db.query.return_value.filter.return_value.first.return_value = None

        result = await session_manager.terminate_session(test_session_id)

        assert result is False
        mock_db.commit.assert_not_called()

    async def test_terminate_session_already_inactive(
        self, session_manager, mock_db, mock_session, test_session_id
    ):
        """Test termination of already inactive session."""
        mock_session.is_active = False
        mock_db.query.return_value.filter.return_value.first.return_value = mock_session

        result = await session_manager.terminate_session(test_session_id)

        assert result is True
        mock_session.terminate.assert_not_called()

    async def test_terminate_session_with_admin_reason(
        self, session_manager, mock_db, mock_session, test_session_id
    ):
        """Test session termination by admin."""
        admin_user_id = uuid4()
        mock_db.query.return_value.filter.return_value.first.return_value = mock_session

        with patch.object(session_manager, '_log_session_activity', new_callable=AsyncMock) as mock_log:
            result = await session_manager.terminate_session(
                test_session_id,
                reason="admin_action",
                terminated_by=admin_user_id
            )

            assert result is True
            mock_session.terminate.assert_called_once_with("admin_action")
            
            # Verify admin ID was logged
            call_args = mock_log.call_args[1]['details']
            assert call_args['terminated_by'] == str(admin_user_id)

    async def test_terminate_session_database_error(self, session_manager, mock_db, test_session_id):
        """Test session termination with database error."""
        mock_db.query.side_effect = Exception("Database error")

        with pytest.raises(Exception):
            await session_manager.terminate_session(test_session_id)


class TestSessionExceptions:
    """Test session exception classes."""

    def test_session_error(self):
        """Test SessionError exception."""
        error = SessionError("Test error")
        assert str(error) == "Test error"
        assert isinstance(error, Exception)

    def test_session_not_found_error(self):
        """Test SessionNotFoundError exception."""
        error = SessionNotFoundError("Session not found")
        assert str(error) == "Session not found"
        assert isinstance(error, SessionError)
        assert isinstance(error, Exception)

    def test_session_expired_error(self):
        """Test SessionExpiredError exception."""
        error = SessionExpiredError("Session expired")
        assert str(error) == "Session expired"
        assert isinstance(error, SessionError)
        assert isinstance(error, Exception)


class TestSessionManagerEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.fixture
    def session_manager(self, mock_db):
        """Create SessionManager instance."""
        return SessionManager(mock_db)

    async def test_create_session_all_optional_parameters(
        self, session_manager, mock_db, mock_user, mock_tenant, test_user_id, test_tenant_id
    ):
        """Test session creation with all optional parameters."""
        def query_side_effect(model):
            query_mock = Mock()
            if model == User:
                query_mock.filter.return_value.first.return_value = mock_user
            elif model == Tenant:
                query_mock.filter.return_value.first.return_value = mock_tenant
            return query_mock
        
        mock_db.query.side_effect = query_side_effect
        mock_db.add = Mock()
        mock_db.commit = Mock()
        mock_db.refresh = Mock()

        device_id = uuid4()
        authentik_session_id = "auth_session_123"
        client_info = {"browser": "Chrome", "os": "Windows"}
        custom_duration = timedelta(hours=6)

        with patch.object(session_manager, '_log_session_activity', new_callable=AsyncMock), \
             patch.object(session_manager, '_check_concurrent_sessions', new_callable=AsyncMock), \
             patch('src.core.auth.session_manager.UserSession') as mock_session_class:

            await session_manager.create_session(
                user_id=test_user_id,
                tenant_id=test_tenant_id,
                ip_address="10.0.0.1",
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                device_id=device_id,
                authentik_session_id=authentik_session_id,
                session_type="mobile",
                login_method="webauthn",
                session_duration=custom_duration,
                client_info=client_info
            )

            args, kwargs = mock_session_class.call_args
            assert kwargs['device_id'] == device_id
            assert kwargs['authentik_session_id'] == authentik_session_id
            assert kwargs['session_type'] == "mobile"
            assert kwargs['login_method'] == "webauthn"
            assert kwargs['client_info'] == client_info

    async def test_validate_session_chain_exceptions(self, session_manager, mock_db, test_session_id):
        """Test session validation exception propagation."""
        # Test SessionNotFoundError propagation
        mock_db.query.return_value.filter.return_value.first.return_value = None
        
        with pytest.raises(SessionNotFoundError):
            await session_manager.validate_session(test_session_id)

        # Test SessionExpiredError propagation
        expired_session = Mock(spec=UserSession)
        expired_session.is_active = True
        expired_session.is_expired.return_value = True
        mock_db.query.return_value.filter.return_value.first.return_value = expired_session

        with patch.object(session_manager, '_log_session_activity', new_callable=AsyncMock):
            with pytest.raises(SessionExpiredError):
                await session_manager.validate_session(test_session_id)

    def test_session_manager_with_custom_default_duration(self, mock_db):
        """Test SessionManager with custom default duration."""
        custom_duration = timedelta(hours=8)
        manager = SessionManager(mock_db, custom_duration)
        
        assert manager.default_session_duration == custom_duration

    async def test_get_user_sessions_with_all_parameters(self, session_manager, mock_db, test_user_id):
        """Test get_user_sessions with all parameter combinations."""
        current_session_id = uuid4()
        mock_sessions = [Mock(spec=UserSession)]
        
        query_mock = Mock()
        query_mock.filter.return_value = query_mock
        query_mock.order_by.return_value.all.return_value = mock_sessions
        mock_db.query.return_value = query_mock

        # Test all combinations
        combinations = [
            (True, True, None),
            (True, False, current_session_id),
            (False, True, None),
            (False, False, current_session_id),
        ]

        for active_only, include_current, current_id in combinations:
            result = await session_manager.get_user_sessions(
                test_user_id,
                active_only=active_only,
                include_current=include_current,
                current_session_id=current_id
            )
            assert result == mock_sessions

    async def test_terminate_session_edge_cases(self, session_manager, mock_db):
        """Test session termination edge cases."""
        test_session_id = uuid4()
        
        # Test with special reason
        mock_session = Mock(spec=UserSession)
        mock_session.is_active = True
        mock_session.created_at = datetime.utcnow() - timedelta(hours=2)
        mock_db.query.return_value.filter.return_value.first.return_value = mock_session

        with patch.object(session_manager, '_log_session_activity', new_callable=AsyncMock):
            result = await session_manager.terminate_session(
                test_session_id,
                reason="security_breach"
            )

            assert result is True
            mock_session.terminate.assert_called_once_with("security_breach")