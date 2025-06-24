"""Unit tests for JWT Manager."""
import pytest
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt

from src.core.auth.jwt_manager import JWTManager, TokenPayload


class TestJWTManager:
    """Test JWT token management."""

    @pytest.fixture
    def jwt_manager(self):
        """Create JWT manager instance."""
        return JWTManager()

    def test_create_access_token(self, jwt_manager):
        """Test access token creation."""
        user_id = "test-user-123"
        tenant_id = "test-tenant-456"
        session_id = "test-session-789"
        scopes = ["read", "write"]
        
        token = jwt_manager.create_access_token(
            user_id=user_id,
            tenant_id=tenant_id,
            session_id=session_id,
            scopes=scopes
        )
        
        # Verify token is a string
        assert isinstance(token, str)
        assert len(token) > 0
        
        # Decode and verify contents
        payload = jwt.decode(
            token,
            jwt_manager.secret_key,
            algorithms=[jwt_manager.algorithm],
            audience=jwt_manager.audience,
            issuer=jwt_manager.issuer
        )
        
        assert payload["sub"] == user_id
        assert payload["tenant_id"] == tenant_id
        assert payload["session_id"] == session_id
        assert payload["scopes"] == scopes
        assert payload["type"] == "access"

    def test_create_refresh_token(self, jwt_manager):
        """Test refresh token creation."""
        user_id = "test-user-123"
        tenant_id = "test-tenant-456"
        session_id = "test-session-789"
        
        token = jwt_manager.create_refresh_token(
            user_id=user_id,
            tenant_id=tenant_id,
            session_id=session_id
        )
        
        # Verify token is a string
        assert isinstance(token, str)
        assert len(token) > 0
        
        # Decode and verify contents
        payload = jwt.decode(
            token,
            jwt_manager.secret_key,
            algorithms=[jwt_manager.algorithm],
            audience=jwt_manager.audience,
            issuer=jwt_manager.issuer
        )
        
        assert payload["sub"] == user_id
        assert payload["tenant_id"] == tenant_id
        assert payload["session_id"] == session_id
        assert payload["type"] == "refresh"

    def test_decode_access_token(self, jwt_manager):
        """Test access token decoding."""
        # Create token
        user_id = "test-user-123"
        tenant_id = "test-tenant-456"
        session_id = "test-session-789"
        scopes = ["read"]
        
        token = jwt_manager.create_access_token(
            user_id=user_id,
            tenant_id=tenant_id,
            session_id=session_id,
            scopes=scopes
        )
        
        # Decode token
        payload = jwt_manager.decode_access_token(token)
        
        assert isinstance(payload, TokenPayload)
        assert payload.sub == user_id
        assert payload.tenant_id == tenant_id
        assert payload.session_id == session_id
        assert payload.scopes == scopes

    def test_decode_invalid_token(self, jwt_manager):
        """Test decoding invalid token."""
        invalid_token = "invalid.token.here"
        
        with pytest.raises(JWTError):
            jwt_manager.decode_access_token(invalid_token)

    def test_decode_expired_token(self, jwt_manager):
        """Test decoding expired token."""
        # Create an expired token
        now = datetime.now(timezone.utc)
        expired_time = now - timedelta(hours=1)
        
        payload = {
            "sub": "test-user",
            "tenant_id": "test-tenant",
            "session_id": "test-session",
            "scopes": [],
            "iat": int((now - timedelta(hours=2)).timestamp()),
            "exp": int(expired_time.timestamp()),
            "iss": jwt_manager.issuer,
            "aud": jwt_manager.audience,
            "type": "access"
        }
        
        expired_token = jwt.encode(
            payload,
            jwt_manager.secret_key,
            algorithm=jwt_manager.algorithm
        )
        
        with pytest.raises(JWTError) as exc_info:
            jwt_manager.decode_access_token(expired_token)
        assert "expired" in str(exc_info.value).lower()

    def test_decode_wrong_token_type(self, jwt_manager):
        """Test decoding token with wrong type."""
        # Create refresh token
        refresh_token = jwt_manager.create_refresh_token(
            user_id="test-user",
            tenant_id="test-tenant",
            session_id="test-session"
        )
        
        # Try to decode as access token
        with pytest.raises(JWTError) as exc_info:
            jwt_manager.decode_access_token(refresh_token)
        assert "Invalid token type" in str(exc_info.value)

    def test_refresh_access_token(self, jwt_manager):
        """Test token refresh flow."""
        # Create initial tokens
        user_id = "test-user-123"
        tenant_id = "test-tenant-456"
        session_id = "test-session-789"
        
        initial_refresh = jwt_manager.create_refresh_token(
            user_id=user_id,
            tenant_id=tenant_id,
            session_id=session_id
        )
        
        # Refresh tokens
        new_access, new_refresh = jwt_manager.refresh_access_token(initial_refresh)
        
        # Verify new tokens
        assert new_access != initial_refresh
        assert new_refresh != initial_refresh
        
        # Decode and verify contents match
        access_payload = jwt_manager.decode_access_token(new_access)
        refresh_payload = jwt_manager.decode_refresh_token(new_refresh)
        
        assert access_payload.sub == user_id
        assert access_payload.tenant_id == tenant_id
        assert access_payload.session_id == session_id
        
        assert refresh_payload.sub == user_id
        assert refresh_payload.tenant_id == tenant_id
        assert refresh_payload.session_id == session_id

    def test_additional_claims(self, jwt_manager):
        """Test adding additional claims to token."""
        additional_claims = {
            "email": "test@example.com",
            "name": "Test User",
            "custom_field": "custom_value"
        }
        
        token = jwt_manager.create_access_token(
            user_id="test-user",
            tenant_id="test-tenant",
            session_id="test-session",
            additional_claims=additional_claims
        )
        
        # Decode raw to check additional claims
        payload = jwt.decode(
            token,
            jwt_manager.secret_key,
            algorithms=[jwt_manager.algorithm],
            audience=jwt_manager.audience,
            issuer=jwt_manager.issuer
        )
        
        assert payload["email"] == additional_claims["email"]
        assert payload["name"] == additional_claims["name"]
        assert payload["custom_field"] == additional_claims["custom_field"]

    def test_token_expiration_times(self, jwt_manager):
        """Test token expiration times are set correctly."""
        # Create tokens
        access_token = jwt_manager.create_access_token(
            user_id="test-user",
            tenant_id="test-tenant",
            session_id="test-session"
        )
        
        refresh_token = jwt_manager.create_refresh_token(
            user_id="test-user",
            tenant_id="test-tenant",
            session_id="test-session"
        )
        
        # Decode payloads
        access_payload = jwt_manager.decode_access_token(access_token)
        refresh_payload = jwt_manager.decode_refresh_token(refresh_token)
        
        # Calculate expected expiration times
        access_exp_delta = access_payload.exp - access_payload.iat
        refresh_exp_delta = refresh_payload.exp - refresh_payload.iat
        
        # Access token should expire in 15 minutes (900 seconds)
        assert 890 <= access_exp_delta <= 910  # Allow small variance
        
        # Refresh token should expire in 30 days
        expected_refresh_seconds = 30 * 24 * 60 * 60  # 30 days in seconds
        assert expected_refresh_seconds - 60 <= refresh_exp_delta <= expected_refresh_seconds + 60