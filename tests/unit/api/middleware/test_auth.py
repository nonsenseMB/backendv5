"""
Unit tests for JWT authentication middleware.
"""
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, MagicMock, patch

from src.api.middleware.auth import (
    JWTValidationMiddleware,
    jwt_validation_middleware,
    PUBLIC_ENDPOINTS,
)
from src.infrastructure.auth.exceptions import (
    AuthentikTokenExpiredError,
    AuthentikValidationError,
)


@pytest.fixture
def test_app():
    """Create a test FastAPI application."""
    app = FastAPI()
    
    @app.middleware("http")
    async def test_middleware(request: Request, call_next):
        return await jwt_validation_middleware(request, call_next)
    
    @app.get("/")
    async def root():
        return {"message": "public endpoint"}
    
    @app.get("/api/v1/protected")
    async def protected(request: Request):
        return {
            "message": "protected endpoint",
            "user_id": getattr(request.state, "user_id", None),
            "tenant_id": getattr(request.state, "tenant_id", None),
        }
    
    @app.get("/health")
    async def health():
        return {"status": "ok"}
    
    return app


@pytest.fixture
def client(test_app):
    """Create a test client."""
    return TestClient(test_app)


class TestJWTValidationMiddleware:
    """Test JWT validation middleware functionality."""
    
    def test_public_endpoints_allowed(self, client):
        """Test that public endpoints don't require authentication."""
        # Test root endpoint
        response = client.get("/")
        assert response.status_code == 200
        assert response.json() == {"message": "public endpoint"}
        
        # Test health endpoint
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}
    
    def test_protected_endpoint_requires_auth(self, client):
        """Test that protected endpoints require authentication."""
        response = client.get("/api/v1/protected")
        assert response.status_code == 401
        assert response.json()["error"] == "unauthorized"
        assert "Missing authentication token" in response.json()["message"]
    
    @pytest.mark.asyncio
    @patch("src.api.middleware.auth.TokenValidator")
    async def test_valid_token_accepted(self, mock_validator_class, client):
        """Test that valid tokens are accepted."""
        # Mock the validator
        mock_validator = AsyncMock()
        mock_validator.validate_access_token.return_value = {
            "sub": "user-123",
            "tenant_id": "tenant-456",
            "sid": "session-789",
            "permissions": ["read", "write"],
            "groups": ["users", "admins"]
        }
        mock_validator_class.return_value = mock_validator
        
        # Make request with valid token
        response = client.get(
            "/api/v1/protected",
            headers={"Authorization": "Bearer valid-token"}
        )
        
        assert response.status_code == 200
        assert response.json()["user_id"] == "user-123"
        assert response.json()["tenant_id"] == "tenant-456"
    
    @pytest.mark.asyncio
    @patch("src.api.middleware.auth.TokenValidator")
    async def test_expired_token_handled(self, mock_validator_class, client):
        """Test that expired tokens are handled properly."""
        # Mock the validator to raise expired error
        mock_validator = AsyncMock()
        mock_validator.validate_access_token.side_effect = AuthentikTokenExpiredError("Token expired")
        mock_validator_class.return_value = mock_validator
        
        # Make request with expired token
        response = client.get(
            "/api/v1/protected",
            headers={"Authorization": "Bearer expired-token"}
        )
        
        assert response.status_code == 401
        assert response.json()["error"] == "token_expired"
        assert "expired" in response.json()["message"].lower()
    
    @pytest.mark.asyncio
    @patch("src.api.middleware.auth.TokenValidator")
    async def test_invalid_token_rejected(self, mock_validator_class, client):
        """Test that invalid tokens are rejected."""
        # Mock the validator to raise validation error
        mock_validator = AsyncMock()
        mock_validator.validate_access_token.side_effect = AuthentikValidationError("Invalid token signature")
        mock_validator_class.return_value = mock_validator
        
        # Make request with invalid token
        response = client.get(
            "/api/v1/protected",
            headers={"Authorization": "Bearer invalid-token"}
        )
        
        assert response.status_code == 401
        assert response.json()["error"] == "invalid_token"
        assert "Invalid" in response.json()["message"]
    
    def test_token_extraction_from_header(self):
        """Test token extraction from Authorization header."""
        middleware = JWTValidationMiddleware(None)
        
        # Test with Bearer token
        request = MagicMock()
        request.headers = {"Authorization": "Bearer test-token-123"}
        request.cookies = {}
        
        token = middleware._extract_token(request)
        assert token == "test-token-123"
        
        # Test without Bearer prefix
        request.headers = {"Authorization": "test-token-456"}
        token = middleware._extract_token(request)
        assert token is None
        
        # Test with no header
        request.headers = {}
        token = middleware._extract_token(request)
        assert token is None
    
    def test_token_extraction_from_cookie(self):
        """Test token extraction from cookies."""
        middleware = JWTValidationMiddleware(None)
        
        # Test with cookie
        request = MagicMock()
        request.headers = {}
        request.cookies = {"access_token": "cookie-token-789"}
        
        token = middleware._extract_token(request)
        assert token == "cookie-token-789"
    
    def test_public_endpoint_detection(self):
        """Test public endpoint detection."""
        middleware = JWTValidationMiddleware(None)
        
        # Test exact matches
        assert middleware._is_public_endpoint("/") is True
        assert middleware._is_public_endpoint("/health") is True
        assert middleware._is_public_endpoint("/docs") is True
        assert middleware._is_public_endpoint("/api/v1/auth/token") is True
        
        # Test pattern matches
        assert middleware._is_public_endpoint("/api/v1/auth/login") is True
        assert middleware._is_public_endpoint("/api/v1/auth/callback") is True
        assert middleware._is_public_endpoint("/static/file.js") is True
        assert middleware._is_public_endpoint("/_health/readiness") is True
        
        # Test protected endpoints
        assert middleware._is_public_endpoint("/api/v1/users") is False
        assert middleware._is_public_endpoint("/api/v1/protected") is False
        assert middleware._is_public_endpoint("/admin") is False
    
    @pytest.mark.asyncio
    @patch("src.api.middleware.auth.TokenValidator")
    async def test_security_headers_added(self, mock_validator_class, client):
        """Test that security headers are added to responses."""
        # Mock the validator
        mock_validator = AsyncMock()
        mock_validator.validate_access_token.return_value = {
            "sub": "user-123",
            "tenant_id": "tenant-456",
            "sid": "session-789"
        }
        mock_validator_class.return_value = mock_validator
        
        # Make request
        response = client.get(
            "/api/v1/protected",
            headers={"Authorization": "Bearer valid-token"}
        )
        
        # Check security headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["X-XSS-Protection"] == "1; mode=block"
    
    def test_refresh_token_extraction(self):
        """Test refresh token extraction."""
        middleware = JWTValidationMiddleware(None)
        
        # Test from header
        request = MagicMock()
        request.headers = {"X-Refresh-Token": "refresh-token-123"}
        request.cookies = {}
        
        token = middleware._extract_refresh_token(request)
        assert token == "refresh-token-123"
        
        # Test from cookie
        request.headers = {}
        request.cookies = {"refresh_token": "refresh-token-456"}
        
        token = middleware._extract_refresh_token(request)
        assert token == "refresh-token-456"
    
    @pytest.mark.asyncio
    @patch("src.api.middleware.auth.TokenValidator")
    async def test_claims_properly_set(self, mock_validator_class, client):
        """Test that all claims are properly set in request state."""
        # Mock the validator with full claims
        mock_validator = AsyncMock()
        mock_validator.validate_access_token.return_value = {
            "sub": "user-123",
            "tenant_id": "tenant-456",
            "sid": "session-789",
            "permissions": ["read", "write", "delete"],
            "groups": ["users", "moderators"],
            "email": "user@example.com",
            "name": "Test User"
        }
        mock_validator_class.return_value = mock_validator
        
        # Create a test endpoint that returns all state
        @client.app.get("/api/v1/test-state")
        async def test_state(request: Request):
            return {
                "user_id": getattr(request.state, "user_id", None),
                "tenant_id": getattr(request.state, "tenant_id", None),
                "session_id": getattr(request.state, "session_id", None),
                "permissions": getattr(request.state, "permissions", None),
                "groups": getattr(request.state, "groups", None),
                "claims": getattr(request.state, "token_claims", None),
            }
        
        # Make request
        response = client.get(
            "/api/v1/test-state",
            headers={"Authorization": "Bearer valid-token"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == "user-123"
        assert data["tenant_id"] == "tenant-456"
        assert data["session_id"] == "session-789"
        assert data["permissions"] == ["read", "write", "delete"]
        assert data["groups"] == ["users", "moderators"]
        assert data["claims"]["email"] == "user@example.com"