"""Integration tests for token exchange service."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

from src.core.auth.jwt_manager import JWTManager
from src.infrastructure.auth.authentik_client import AuthentikClient
from src.infrastructure.auth.exceptions import AuthentikAuthenticationError
from src.infrastructure.auth.token_exchange import (
    TokenExchangeRequest,
    TokenExchangeService,
    UserInfo,
)
from src.infrastructure.auth.token_validator import TokenValidator


@pytest.fixture
def mock_authentik_client():
    """Mock Authentik client."""
    return MagicMock(spec=AuthentikClient)


@pytest.fixture
def mock_token_validator():
    """Mock token validator."""
    validator = MagicMock(spec=TokenValidator)
    return validator


@pytest.fixture
def jwt_manager():
    """Real JWT manager for testing."""
    return JWTManager()


@pytest.fixture
def token_exchange_service(mock_authentik_client, mock_token_validator, jwt_manager):
    """Token exchange service with mocked dependencies."""
    return TokenExchangeService(
        authentik_client=mock_authentik_client,
        token_validator=mock_token_validator,
        jwt_manager=jwt_manager,
    )


class TestTokenExchange:
    """Test token exchange functionality."""

    @pytest.mark.asyncio
    async def test_successful_token_exchange(self, token_exchange_service, mock_token_validator):
        """Test successful token exchange."""
        # Setup
        tenant_id = uuid4()
        authentik_token = "valid-authentik-token"
        
        # Mock token validation response
        mock_token_validator.validate_token = AsyncMock(return_value={
            "sub": "auth-user-123",
            "email": "user@example.com",
            "email_verified": True,
            "name": "Test User",
            "groups": ["users"],
            "attributes": {"department": "engineering"},
            "sid": "session-123"
        })
        
        # Execute
        request = TokenExchangeRequest(
            authentik_token=authentik_token,
            tenant_id=tenant_id
        )
        response = await token_exchange_service.exchange_token(request)
        
        # Verify
        assert response.access_token
        assert response.refresh_token
        assert response.token_type == "Bearer"
        assert response.expires_in == 900  # 15 minutes
        
        # Verify tokens can be decoded
        access_payload = token_exchange_service.jwt_manager.decode_access_token(response.access_token)
        assert access_payload.tenant_id == str(tenant_id)
        assert "user@example.com" in response.access_token  # Email should be in additional claims

    @pytest.mark.asyncio
    async def test_token_exchange_invalid_token(self, token_exchange_service, mock_token_validator):
        """Test token exchange with invalid Authentik token."""
        # Setup
        tenant_id = uuid4()
        authentik_token = "invalid-token"
        
        # Mock token validation to raise error
        mock_token_validator.validate_token = AsyncMock(
            side_effect=AuthentikAuthenticationError("Invalid token")
        )
        
        # Execute and verify
        request = TokenExchangeRequest(
            authentik_token=authentik_token,
            tenant_id=tenant_id
        )
        
        with pytest.raises(AuthentikAuthenticationError):
            await token_exchange_service.exchange_token(request)

    @pytest.mark.asyncio
    async def test_token_exchange_with_admin_user(self, token_exchange_service, mock_token_validator):
        """Test token exchange for admin user."""
        # Setup
        tenant_id = uuid4()
        authentik_token = "admin-token"
        
        # Mock admin user token
        mock_token_validator.validate_token = AsyncMock(return_value={
            "sub": "admin-user-123",
            "email": "admin@example.com",
            "email_verified": True,
            "name": "Admin User",
            "groups": ["admins", "users"],
            "attributes": {},
            "sid": "admin-session-123"
        })
        
        # Execute
        request = TokenExchangeRequest(
            authentik_token=authentik_token,
            tenant_id=tenant_id
        )
        response = await token_exchange_service.exchange_token(request)
        
        # Verify admin has proper scopes
        access_payload = token_exchange_service.jwt_manager.decode_access_token(response.access_token)
        # Admin group should grant all scopes
        assert "admin" in access_payload.scopes
        assert "read" in access_payload.scopes
        assert "write" in access_payload.scopes
        assert "delete" in access_payload.scopes

    @pytest.mark.asyncio
    async def test_tenant_access_verification(self, token_exchange_service, mock_token_validator):
        """Test tenant access verification."""
        # Setup
        tenant_id = uuid4()
        other_tenant_id = uuid4()
        authentik_token = "user-token"
        
        # Mock user with specific tenant access
        mock_token_validator.validate_token = AsyncMock(return_value={
            "sub": "user-456",
            "email": "user@example.com",
            "email_verified": True,
            "groups": [f"tenant:{tenant_id}"],
            "attributes": {},
            "sid": "session-456"
        })
        
        # Execute - should succeed for allowed tenant
        request = TokenExchangeRequest(
            authentik_token=authentik_token,
            tenant_id=tenant_id
        )
        response = await token_exchange_service.exchange_token(request)
        assert response.access_token

    @pytest.mark.asyncio
    async def test_refresh_token_flow(self, token_exchange_service, mock_token_validator):
        """Test refresh token flow."""
        # Setup - first get tokens via exchange
        tenant_id = uuid4()
        authentik_token = "valid-token"
        
        mock_token_validator.validate_token = AsyncMock(return_value={
            "sub": "user-789",
            "email": "user@example.com",
            "email_verified": True,
            "groups": ["users"],
            "attributes": {},
            "sid": "session-789"
        })
        
        # Get initial tokens
        request = TokenExchangeRequest(
            authentik_token=authentik_token,
            tenant_id=tenant_id
        )
        initial_response = await token_exchange_service.exchange_token(request)
        
        # Refresh tokens
        refreshed_response = await token_exchange_service.refresh_token(
            initial_response.refresh_token
        )
        
        # Verify new tokens
        assert refreshed_response.access_token != initial_response.access_token
        assert refreshed_response.refresh_token != initial_response.refresh_token
        assert refreshed_response.expires_in == 900
        
        # Verify new tokens maintain same user/tenant/session
        initial_payload = token_exchange_service.jwt_manager.decode_refresh_token(
            initial_response.refresh_token
        )
        refreshed_payload = token_exchange_service.jwt_manager.decode_access_token(
            refreshed_response.access_token
        )
        
        assert initial_payload.sub == refreshed_payload.sub
        assert initial_payload.tenant_id == refreshed_payload.tenant_id
        assert initial_payload.session_id == refreshed_payload.session_id

    @pytest.mark.asyncio
    async def test_scope_extraction(self, token_exchange_service):
        """Test scope extraction from user groups."""
        # Test admin scopes
        admin_user = UserInfo(
            sub="admin-1",
            email="admin@test.com",
            groups=["admins"],
            attributes={}
        )
        admin_scopes = token_exchange_service._extract_scopes(admin_user)
        assert set(admin_scopes) == {"admin", "read", "write", "delete"}
        
        # Test regular user scopes
        user = UserInfo(
            sub="user-1",
            email="user@test.com",
            groups=["users"],
            attributes={}
        )
        user_scopes = token_exchange_service._extract_scopes(user)
        assert set(user_scopes) == {"read", "write"}
        
        # Test viewer scopes
        viewer = UserInfo(
            sub="viewer-1",
            email="viewer@test.com",
            groups=["viewers"],
            attributes={}
        )
        viewer_scopes = token_exchange_service._extract_scopes(viewer)
        assert set(viewer_scopes) == {"read"}
        
        # Test custom scopes from attributes
        custom_user = UserInfo(
            sub="custom-1",
            email="custom@test.com",
            groups=["users"],
            attributes={"scopes": ["custom1", "custom2"]}
        )
        custom_scopes = token_exchange_service._extract_scopes(custom_user)
        assert "read" in custom_scopes
        assert "write" in custom_scopes
        assert "custom1" in custom_scopes
        assert "custom2" in custom_scopes


class TestTokenExchangeAPI:
    """Test token exchange API endpoints."""

    @pytest.mark.asyncio
    async def test_exchange_endpoint(self, client, mock_token_validator):
        """Test /api/v1/auth/token/exchange endpoint."""
        # This would require a test client setup
        # Placeholder for API-level testing
        pass

    @pytest.mark.asyncio
    async def test_refresh_endpoint(self, client):
        """Test /api/v1/auth/token/refresh endpoint."""
        # This would require a test client setup
        # Placeholder for API-level testing
        pass