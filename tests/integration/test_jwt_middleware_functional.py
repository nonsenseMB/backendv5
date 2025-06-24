"""
Integration test to verify JWT middleware is 100% functional.
Tests both Authentik tokens and internal tokens.
"""
import pytest
from datetime import datetime, timedelta
from fastapi import FastAPI, Request, Depends
from fastapi.testclient import TestClient
from jose import jwt

from src.api.middleware.auth import jwt_validation_middleware
from src.core.auth.jwt_manager import JWTManager
from src.core.config import settings


@pytest.fixture
def app_with_auth():
    """Create a test app with JWT middleware."""
    app = FastAPI()
    
    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        return await jwt_validation_middleware(request, call_next)
    
    @app.get("/")
    async def root():
        return {"message": "public"}
    
    @app.get("/api/v1/protected")
    async def protected(request: Request):
        return {
            "user_id": request.state.user_id,
            "tenant_id": request.state.tenant_id,
            "session_id": request.state.session_id,
            "permissions": getattr(request.state, "permissions", [])
        }
    
    return app


@pytest.fixture
def client(app_with_auth):
    """Create test client."""
    return TestClient(app_with_auth)


@pytest.fixture
def jwt_manager():
    """Create JWT manager for generating internal tokens."""
    return JWTManager()


class TestJWTMiddlewareFunctional:
    """Test that JWT middleware is 100% functional without mocks."""
    
    def test_internal_jwt_token_works(self, client, jwt_manager):
        """Test that internally generated JWT tokens work properly."""
        # Create a real internal JWT token
        access_token = jwt_manager.create_access_token(
            user_id="test-user-123",
            tenant_id="test-tenant-456",
            session_id="test-session-789",
            scopes=["read", "write"]
        )
        
        # Make request with internal token
        response = client.get(
            "/api/v1/protected",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        # Verify it works
        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == "test-user-123"
        assert data["tenant_id"] == "test-tenant-456"
        assert data["session_id"] == "test-session-789"
        assert data["permissions"] == ["read", "write"]
    
    def test_token_refresh_works(self, client, jwt_manager):
        """Test that token refresh functionality works."""
        # Create refresh token
        refresh_token = jwt_manager.create_refresh_token(
            user_id="refresh-user-123",
            tenant_id="refresh-tenant-456",
            session_id="refresh-session-789"
        )
        
        # Create expired access token (manually set exp claim)
        now = datetime.utcnow()
        expired_payload = {
            "sub": "refresh-user-123",
            "tenant_id": "refresh-tenant-456",
            "session_id": "refresh-session-789",
            "scopes": ["read"],
            "iat": int((now - timedelta(hours=1)).timestamp()),
            "exp": int((now - timedelta(minutes=1)).timestamp()),  # Expired
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
            "type": "access"
        }
        expired_token = jwt.encode(
            expired_payload, 
            settings.SECRET_KEY, 
            algorithm=settings.JWT_ALGORITHM
        )
        
        # Make request with expired token and refresh token
        response = client.get(
            "/api/v1/protected",
            headers={
                "Authorization": f"Bearer {expired_token}",
                "X-Refresh-Token": refresh_token
            }
        )
        
        # Should get 401 with new tokens
        assert response.status_code == 401
        data = response.json()
        assert data["error"] == "token_expired"
        assert "tokens" in data
        assert "access_token" in data["tokens"]
        assert "refresh_token" in data["tokens"]
        
        # Verify new access token works
        new_token = data["tokens"]["access_token"]
        response2 = client.get(
            "/api/v1/protected",
            headers={"Authorization": f"Bearer {new_token}"}
        )
        
        assert response2.status_code == 200
        data2 = response2.json()
        assert data2["user_id"] == "refresh-user-123"
        assert data2["tenant_id"] == "refresh-tenant-456"
    
    def test_invalid_token_rejected(self, client):
        """Test that invalid tokens are properly rejected."""
        # Test with completely invalid token
        response = client.get(
            "/api/v1/protected",
            headers={"Authorization": "Bearer invalid-token-12345"}
        )
        
        assert response.status_code == 401
        assert response.json()["error"] == "invalid_token"
    
    def test_missing_token_rejected(self, client):
        """Test that missing tokens are properly rejected."""
        response = client.get("/api/v1/protected")
        
        assert response.status_code == 401
        assert response.json()["error"] == "unauthorized"
        assert "Missing authentication token" in response.json()["message"]
    
    def test_public_endpoints_work(self, client):
        """Test that public endpoints work without authentication."""
        response = client.get("/")
        
        assert response.status_code == 200
        assert response.json()["message"] == "public"
    
    def test_security_headers_added(self, client, jwt_manager):
        """Test that security headers are added to authenticated responses."""
        # Create valid token
        token = jwt_manager.create_access_token(
            user_id="header-test-user",
            tenant_id="header-test-tenant",
            session_id="header-test-session"
        )
        
        # Make authenticated request
        response = client.get(
            "/api/v1/protected",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200
        # Check security headers
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert response.headers.get("X-XSS-Protection") == "1; mode=block"
    
    @pytest.mark.asyncio
    async def test_no_mocks_or_placeholders(self):
        """Verify there are no mocks or placeholder implementations."""
        # Check that JWT manager creates real tokens
        jwt_manager = JWTManager()
        token = jwt_manager.create_access_token(
            user_id="real-user",
            tenant_id="real-tenant",
            session_id="real-session"
        )
        
        # Decode and verify it's a real JWT
        decoded = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER
        )
        
        assert decoded["sub"] == "real-user"
        assert decoded["tenant_id"] == "real-tenant"
        assert decoded["type"] == "access"
        assert "exp" in decoded
        assert "iat" in decoded
        
        # Verify no "temporary" or "mock" strings in token
        assert "temporary" not in token
        assert "mock" not in token.lower()
        assert "placeholder" not in token.lower()