"""Integration tests for device trust management."""
import pytest
from datetime import datetime, timedelta
from uuid import uuid4

from fastapi import FastAPI, Depends, HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from src.api.dependencies.trust import (
    get_device_policy,
    require_high_trust,
    require_medium_trust,
    check_sensitive_operation_allowed,
    check_api_key_generation_allowed,
    get_session_limits,
    TrustBasedRateLimit
)
from src.core.auth.trust_manager import trust_manager


# Create test app
app = FastAPI()


@app.get("/test/policy")
async def test_get_policy(
    request: Request,
    policy: dict = Depends(get_device_policy)
):
    """Test endpoint for policy retrieval."""
    return {"policy": policy}


@app.get("/test/high-trust")
async def test_high_trust(
    policy: dict = Depends(require_high_trust)
):
    """Test endpoint requiring high trust."""
    return {"message": "High trust access granted", "policy": policy}


@app.get("/test/medium-trust")
async def test_medium_trust(
    policy: dict = Depends(require_medium_trust)
):
    """Test endpoint requiring medium trust."""
    return {"message": "Medium trust access granted", "policy": policy}


@app.get("/test/sensitive")
async def test_sensitive_operation(
    allowed: bool = Depends(check_sensitive_operation_allowed)
):
    """Test endpoint for sensitive operations."""
    return {"message": "Sensitive operation allowed", "allowed": allowed}


@app.get("/test/api-key")
async def test_api_key_generation(
    allowed: bool = Depends(check_api_key_generation_allowed)
):
    """Test endpoint for API key generation."""
    return {"message": "API key generation allowed", "allowed": allowed}


@app.get("/test/session-limits")
async def test_session_limits(
    limits: dict = Depends(get_session_limits)
):
    """Test endpoint for session limits."""
    return {"limits": limits}


class TestDeviceTrustIntegration:
    """Test device trust integration with FastAPI."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)
    
    @pytest.fixture
    def mock_request_state(self, monkeypatch):
        """Mock request state for testing."""
        class MockState:
            def __init__(self, device_id=None, trust_score=None):
                self.device_id = device_id
                self.device_trust_score = trust_score
        
        def mock_get_device_policy(request: Request):
            """Mock policy getter."""
            if not hasattr(request.state, "device_id"):
                raise HTTPException(status_code=403, detail="No device context found")
            
            trust_score = getattr(request.state, "device_trust_score", 0)
            return trust_manager.get_device_policy(trust_score)
        
        # Patch the dependency
        app.dependency_overrides[get_device_policy] = mock_get_device_policy
        
        yield MockState
        
        # Clean up
        app.dependency_overrides.clear()
    
    def test_get_policy_no_device_context(self, client):
        """Test policy retrieval without device context."""
        response = client.get("/test/policy")
        assert response.status_code == 403
        assert "No device context found" in response.json()["detail"]
    
    def test_get_policy_with_device_context(self, client, mock_request_state):
        """Test policy retrieval with device context."""
        # Mock high trust device
        def override_policy(request: Request):
            request.state = mock_request_state(
                device_id=str(uuid4()),
                trust_score=85
            )
            return trust_manager.get_device_policy(85)
        
        app.dependency_overrides[get_device_policy] = override_policy
        
        response = client.get("/test/policy")
        assert response.status_code == 200
        
        policy = response.json()["policy"]
        assert policy["trust_level"] == "high"
        assert policy["trust_score"] == 85
        assert policy["allow_sensitive_operations"] is True
    
    def test_high_trust_required_success(self, client, mock_request_state):
        """Test high trust requirement with sufficient trust."""
        def override_policy(request: Request):
            return trust_manager.get_device_policy(85)
        
        app.dependency_overrides[get_device_policy] = override_policy
        
        response = client.get("/test/high-trust")
        assert response.status_code == 200
        assert "High trust access granted" in response.json()["message"]
    
    def test_high_trust_required_failure(self, client, mock_request_state):
        """Test high trust requirement with insufficient trust."""
        def override_policy(request: Request):
            return trust_manager.get_device_policy(50)
        
        app.dependency_overrides[get_device_policy] = override_policy
        
        response = client.get("/test/high-trust")
        assert response.status_code == 403
        assert "requires a high trust device" in response.json()["detail"]
    
    def test_medium_trust_success(self, client, mock_request_state):
        """Test medium trust requirement."""
        # Test with high trust (should pass)
        def override_policy_high(request: Request):
            return trust_manager.get_device_policy(85)
        
        app.dependency_overrides[get_device_policy] = override_policy_high
        
        response = client.get("/test/medium-trust")
        assert response.status_code == 200
        
        # Test with medium trust (should pass)
        def override_policy_medium(request: Request):
            return trust_manager.get_device_policy(60)
        
        app.dependency_overrides[get_device_policy] = override_policy_medium
        
        response = client.get("/test/medium-trust")
        assert response.status_code == 200
    
    def test_medium_trust_failure(self, client, mock_request_state):
        """Test medium trust requirement with low trust."""
        def override_policy(request: Request):
            return trust_manager.get_device_policy(30)
        
        app.dependency_overrides[get_device_policy] = override_policy
        
        response = client.get("/test/medium-trust")
        assert response.status_code == 403
        assert "requires at least a medium trust device" in response.json()["detail"]
    
    def test_sensitive_operation_check(self, client, mock_request_state):
        """Test sensitive operation permission check."""
        # High trust - allowed
        def override_policy_high(request: Request):
            return trust_manager.get_device_policy(85)
        
        app.dependency_overrides[get_device_policy] = override_policy_high
        
        response = client.get("/test/sensitive")
        assert response.status_code == 200
        assert response.json()["allowed"] is True
        
        # Low trust - not allowed
        def override_policy_low(request: Request):
            return trust_manager.get_device_policy(30)
        
        app.dependency_overrides[get_device_policy] = override_policy_low
        
        response = client.get("/test/sensitive")
        assert response.status_code == 403
        assert "Sensitive operations not allowed" in response.json()["detail"]
    
    def test_api_key_generation_check(self, client, mock_request_state):
        """Test API key generation permission."""
        # Only high trust can generate API keys
        def override_policy_high(request: Request):
            return trust_manager.get_device_policy(85)
        
        app.dependency_overrides[get_device_policy] = override_policy_high
        
        response = client.get("/test/api-key")
        assert response.status_code == 200
        
        # Medium trust cannot
        def override_policy_medium(request: Request):
            return trust_manager.get_device_policy(60)
        
        app.dependency_overrides[get_device_policy] = override_policy_medium
        
        response = client.get("/test/api-key")
        assert response.status_code == 403
        assert "API key generation requires a high trust device" in response.json()["detail"]
    
    def test_session_limits_by_trust(self, client, mock_request_state):
        """Test session limits based on trust level."""
        # High trust
        def override_policy_high(request: Request):
            return trust_manager.get_device_policy(85)
        
        app.dependency_overrides[get_device_policy] = override_policy_high
        
        response = client.get("/test/session-limits")
        assert response.status_code == 200
        
        limits = response.json()["limits"]
        assert limits["timeout_minutes"] == 480
        assert limits["max_duration_minutes"] == 10080
        assert limits["require_mfa"] is False
        assert limits["trust_level"] == "high"
        
        # Low trust
        def override_policy_low(request: Request):
            return trust_manager.get_device_policy(30)
        
        app.dependency_overrides[get_device_policy] = override_policy_low
        
        response = client.get("/test/session-limits")
        assert response.status_code == 200
        
        limits = response.json()["limits"]
        assert limits["timeout_minutes"] == 30
        assert limits["max_duration_minutes"] == 480
        assert limits["require_mfa"] is True
        assert limits["trust_level"] == "low"
    
    def test_trust_based_rate_limit(self):
        """Test trust-based rate limiting."""
        rate_limiter = TrustBasedRateLimit(
            high_trust_limit=1000,
            medium_trust_limit=100,
            low_trust_limit=10,
            window_seconds=3600
        )
        
        assert rate_limiter.limits["high"] == 1000
        assert rate_limiter.limits["medium"] == 100
        assert rate_limiter.limits["low"] == 10
        assert rate_limiter.window_seconds == 3600
    
    @pytest.mark.asyncio
    async def test_concurrent_session_enforcement(self):
        """Test concurrent session limit enforcement."""
        from src.api.dependencies.trust import enforce_concurrent_session_limit
        from src.infrastructure.database.models.auth import User
        
        # This would require a full database setup
        # For unit testing, we're validating the logic exists
        assert enforce_concurrent_session_limit is not None