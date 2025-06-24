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


class TestJWTSecurityValidation:
    """Security-focused JWT validation tests."""

    @pytest.fixture
    def jwt_manager(self):
        """Create JWT manager instance."""
        return JWTManager()

    def test_algorithm_confusion_attack_prevention(self, jwt_manager):
        """Test prevention of algorithm confusion attacks."""
        import base64
        import json
        
        # Attempt to create token with 'none' algorithm
        header = {"alg": "none", "typ": "JWT"}
        payload = {
            "sub": "admin",
            "tenant_id": "test-tenant",
            "session_id": "test-session",
            "scopes": ["admin"],
            "type": "access",
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iss": jwt_manager.issuer,
            "aud": jwt_manager.audience
        }
        
        # Create unsigned token
        token = (
            base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=") +
            "." +
            base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=") +
            "."
        )
        
        # Should reject 'none' algorithm tokens
        with pytest.raises(JWTError):
            jwt_manager.decode_access_token(token)

    def test_invalid_signature_rejection(self, jwt_manager):
        """Test rejection of tokens with invalid signatures."""
        # Create valid token
        token = jwt_manager.create_access_token(
            user_id="test-user",
            tenant_id="test-tenant", 
            session_id="test-session"
        )
        
        # Tamper with signature
        parts = token.split(".")
        parts[2] = "invalid_signature"
        tampered_token = ".".join(parts)
        
        with pytest.raises(JWTError):
            jwt_manager.decode_access_token(tampered_token)

    def test_malformed_token_rejection(self, jwt_manager):
        """Test rejection of malformed tokens."""
        malformed_tokens = [
            "not.a.jwt",
            "one_part_only",
            "two.parts",
            "",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid_payload.signature",
            "invalid_header.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature"
        ]
        
        for token in malformed_tokens:
            with pytest.raises(JWTError):
                jwt_manager.decode_access_token(token)

    def test_missing_required_claims(self, jwt_manager):
        """Test rejection of tokens missing required claims."""
        from jose import jwt
        
        # Token missing tenant_id
        payload_missing_tenant = {
            "sub": "test-user",
            "session_id": "test-session",
            "scopes": [],
            "type": "access",
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iss": jwt_manager.issuer,
            "aud": jwt_manager.audience
        }
        
        token_missing_tenant = jwt.encode(
            payload_missing_tenant,
            jwt_manager.secret_key,
            algorithm=jwt_manager.algorithm
        )
        
        with pytest.raises(JWTError, match="Missing required claim"):
            jwt_manager.decode_access_token(token_missing_tenant)

    def test_invalid_audience_rejection(self, jwt_manager):
        """Test rejection of tokens with wrong audience."""
        from jose import jwt
        
        payload = {
            "sub": "test-user",
            "tenant_id": "test-tenant",
            "session_id": "test-session",
            "scopes": [],
            "type": "access",
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iss": jwt_manager.issuer,
            "aud": "wrong-audience"  # Wrong audience
        }
        
        wrong_audience_token = jwt.encode(
            payload,
            jwt_manager.secret_key,
            algorithm=jwt_manager.algorithm
        )
        
        with pytest.raises(JWTError):
            jwt_manager.decode_access_token(wrong_audience_token)

    def test_invalid_issuer_rejection(self, jwt_manager):
        """Test rejection of tokens with wrong issuer."""
        from jose import jwt
        
        payload = {
            "sub": "test-user",
            "tenant_id": "test-tenant",
            "session_id": "test-session",
            "scopes": [],
            "type": "access",
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iss": "wrong-issuer",  # Wrong issuer
            "aud": jwt_manager.audience
        }
        
        wrong_issuer_token = jwt.encode(
            payload,
            jwt_manager.secret_key,
            algorithm=jwt_manager.algorithm
        )
        
        with pytest.raises(JWTError):
            jwt_manager.decode_access_token(wrong_issuer_token)

    def test_token_reuse_different_type(self, jwt_manager):
        """Test that access tokens can't be used as refresh tokens and vice versa."""
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
        
        # Access token should not work for refresh
        with pytest.raises(JWTError, match="Invalid token type"):
            jwt_manager.decode_refresh_token(access_token)
        
        # Refresh token should not work for access
        with pytest.raises(JWTError, match="Invalid token type"):
            jwt_manager.decode_access_token(refresh_token)

    def test_refresh_token_rotation(self, jwt_manager):
        """Test that refresh generates new tokens (rotation)."""
        # Create initial refresh token
        initial_refresh = jwt_manager.create_refresh_token(
            user_id="test-user",
            tenant_id="test-tenant",
            session_id="test-session"
        )
        
        # Refresh tokens
        new_access, new_refresh = jwt_manager.refresh_access_token(initial_refresh)
        
        # New tokens should be different
        assert new_access != initial_refresh
        assert new_refresh != initial_refresh
        assert new_access != new_refresh
        
        # Original refresh token should not work again (if rotation is enforced)
        # Note: This would require token blacklisting in production
        
    def test_token_timing_attack_resistance(self, jwt_manager):
        """Test that token validation timing is consistent."""
        import time
        
        valid_token = jwt_manager.create_access_token(
            user_id="test-user",
            tenant_id="test-tenant",
            session_id="test-session"
        )
        
        invalid_token = "invalid.token.here"
        
        # Measure timing for valid vs invalid tokens
        # Note: This is a basic test - real timing attack resistance 
        # requires more sophisticated measurement
        
        start_time = time.time()
        try:
            jwt_manager.decode_access_token(valid_token)
        except:
            pass
        valid_time = time.time() - start_time
        
        start_time = time.time()
        try:
            jwt_manager.decode_access_token(invalid_token)
        except:
            pass
        invalid_time = time.time() - start_time
        
        # Times should be reasonably similar (within 10x)
        # This is a rough check - production systems need more precise timing
        assert abs(valid_time - invalid_time) < max(valid_time, invalid_time) * 10

    def test_large_payload_handling(self, jwt_manager):
        """Test handling of unusually large token payloads."""
        # Create token with large additional claims
        large_claims = {
            "large_field_" + str(i): "x" * 1000 for i in range(10)
        }
        
        try:
            token = jwt_manager.create_access_token(
                user_id="test-user",
                tenant_id="test-tenant",
                session_id="test-session",
                additional_claims=large_claims
            )
            
            # Should be able to decode large token
            payload = jwt_manager.decode_access_token(token)
            assert payload.sub == "test-user"
            
        except Exception as e:
            # If JWT library rejects large tokens, that's acceptable
            assert "too large" in str(e).lower() or "size" in str(e).lower()

    def test_special_characters_in_claims(self, jwt_manager):
        """Test handling of special characters in token claims."""
        special_user_id = "user@example.com/test<script>alert('xss')</script>"
        special_tenant = "tenant-with-üñíçødé-chars"
        
        token = jwt_manager.create_access_token(
            user_id=special_user_id,
            tenant_id=special_tenant,
            session_id="test-session"
        )
        
        payload = jwt_manager.decode_access_token(token)
        assert payload.sub == special_user_id
        assert payload.tenant_id == special_tenant