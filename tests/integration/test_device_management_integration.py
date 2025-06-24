"""Integration tests for device management API."""
import asyncio
import pytest
from datetime import datetime, timedelta
from uuid import uuid4
from unittest.mock import AsyncMock, patch

from src.api.v1.auth.device_management import (
    calculate_overall_security_score,
    generate_security_recommendations,
    perform_comprehensive_security_check
)
from src.infrastructure.database.models.auth import UserDevice


class TestDeviceManagementIntegration:
    """Test device management integration functionality."""
    
    @pytest.fixture
    def sample_devices(self):
        """Create sample devices for testing."""
        now = datetime.utcnow()
        
        devices = [
            # High trust, recently used device
            UserDevice(
                id=uuid4(),
                user_id=uuid4(),
                device_name="iPhone 15 Pro",
                device_type="webauthn",
                trust_score=85.0,
                is_trusted=True,
                is_active=True,
                last_used_at=now - timedelta(hours=1),
                created_at=now - timedelta(days=30)
            ),
            
            # Medium trust device
            UserDevice(
                id=uuid4(),
                user_id=uuid4(),
                device_name="MacBook Pro",
                device_type="webauthn",
                trust_score=65.0,
                is_trusted=False,
                is_active=True,
                last_used_at=now - timedelta(days=5),
                created_at=now - timedelta(days=60)
            ),
            
            # Low trust, old device
            UserDevice(
                id=uuid4(),
                user_id=uuid4(),
                device_name="Old Android",
                device_type="webauthn",
                trust_score=30.0,
                is_trusted=False,
                is_active=True,
                last_used_at=now - timedelta(days=45),
                created_at=now - timedelta(days=400)
            ),
            
            # Inactive device
            UserDevice(
                id=uuid4(),
                user_id=uuid4(),
                device_name="Inactive Device",
                device_type="certificate",
                trust_score=50.0,
                is_trusted=False,
                is_active=False,
                last_used_at=now - timedelta(days=100),
                created_at=now - timedelta(days=200)
            )
        ]
        
        return devices
    
    def test_calculate_overall_security_score(self, sample_devices):
        """Test overall security score calculation."""
        # Test with all devices
        score = calculate_overall_security_score(sample_devices)
        
        # Should calculate average of active devices: (85 + 65 + 30) / 3 = 60
        # With penalty for old device: 60 - 2 = 58
        assert 55 <= score <= 65  # Allow some variance
        
        # Test with empty device list
        score = calculate_overall_security_score([])
        assert score == 0
        
        # Test with only inactive devices
        inactive_devices = [d for d in sample_devices if not d.is_active]
        score = calculate_overall_security_score(inactive_devices)
        assert score == 0
    
    def test_generate_security_recommendations(self, sample_devices):
        """Test security recommendations generation."""
        recommendations = generate_security_recommendations(sample_devices)
        
        # Should have recommendations for low trust and unused devices
        assert len(recommendations) > 0
        
        # Check for specific recommendations
        recommendation_text = " ".join(recommendations)
        assert "low-trust" in recommendation_text.lower()
        assert "not used" in recommendation_text.lower()
        
        # Test with high-trust devices only
        high_trust_devices = [
            UserDevice(
                id=uuid4(),
                user_id=uuid4(),
                device_name="Trusted Device",
                device_type="webauthn",
                trust_score=90.0,
                is_trusted=True,
                is_active=True,
                last_used_at=datetime.utcnow() - timedelta(hours=1),
                created_at=datetime.utcnow() - timedelta(days=10)
            )
        ]
        
        recommendations = generate_security_recommendations(high_trust_devices)
        # Should have fewer or no recommendations
        assert len(recommendations) <= 1
    
    @pytest.mark.asyncio
    async def test_perform_comprehensive_security_check(self, sample_devices):
        """Test comprehensive security check."""
        device = sample_devices[2]  # Low trust, old device
        
        with patch('src.api.v1.auth.device_management.trust_manager') as mock_trust_manager:
            mock_trust_manager.get_device_analytics.return_value = {
                "failed_auth_count": 2,
                "successful_auth_count": 10,
                "success_rate": 0.83
            }
            
            check_result = await perform_comprehensive_security_check(
                device=device,
                check_type="full"
            )
            
            assert check_result["device_id"] == str(device.id)
            assert check_result["device_name"] == device.device_name
            assert check_result["check_type"] == "full"
            assert "security_score" in check_result
            assert "issues" in check_result
            assert "recommendations" in check_result
            
            # Should find issues with old, low-trust device
            assert len(check_result["issues"]) > 0
            assert len(check_result["recommendations"]) > 0
            
            # Check for specific issues
            issues_text = " ".join(check_result["issues"])
            assert "over 1 year old" in issues_text or "not used" in issues_text
    
    @pytest.mark.asyncio
    async def test_security_check_with_high_trust_device(self, sample_devices):
        """Test security check with high trust device."""
        device = sample_devices[0]  # High trust device
        
        with patch('src.api.v1.auth.device_management.trust_manager') as mock_trust_manager:
            mock_trust_manager.get_device_analytics.return_value = {
                "failed_auth_count": 0,
                "successful_auth_count": 50,
                "success_rate": 1.0
            }
            
            check_result = await perform_comprehensive_security_check(
                device=device,
                check_type="basic"
            )
            
            # Should have fewer issues
            assert check_result["security_score"] >= 70
            assert check_result["compliance_status"] == "compliant"
            assert len(check_result["issues"]) <= 1  # Maybe device age
    
    def test_get_risk_level(self):
        """Test risk level calculation."""
        from src.api.v1.auth.device_management import get_risk_level
        
        assert get_risk_level(90) == "low"
        assert get_risk_level(70) == "medium"
        assert get_risk_level(50) == "high"
        assert get_risk_level(30) == "critical"
    
    @pytest.mark.asyncio
    async def test_device_removal_confirmation_generation(self):
        """Test device removal confirmation code generation."""
        from src.api.v1.auth.device_management import (
            generate_device_removal_confirmation,
            validate_device_removal_confirmation
        )
        
        user_id = uuid4()
        device_id = uuid4()
        
        # Generate confirmation code
        code = await generate_device_removal_confirmation(user_id, device_id)
        
        assert isinstance(code, str)
        assert len(code) == 12
        
        # Validate the code
        is_valid = await validate_device_removal_confirmation(user_id, device_id, code)
        assert is_valid is True
        
        # Test with wrong code
        is_valid = await validate_device_removal_confirmation(user_id, device_id, "wrong_code")
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_device_operation_rate_limiter(self):
        """Test device operation rate limiting."""
        from src.api.middleware.rate_limiter import DeviceOperationRateLimiter
        from unittest.mock import AsyncMock
        
        rate_limiter = DeviceOperationRateLimiter()
        user_id = uuid4()
        
        # Mock Redis client
        mock_redis = AsyncMock()
        mock_redis.incr.return_value = 1
        mock_redis.expire.return_value = True
        
        # Should allow operation within limits
        result = await rate_limiter.check_device_operation_limit(
            user_id=user_id,
            operation="device_registration",
            redis_client=mock_redis
        )
        
        assert result is True
        assert mock_redis.incr.call_count == 2  # Hour and day counters
        assert mock_redis.expire.call_count == 2
    
    @pytest.mark.asyncio
    async def test_device_operation_rate_limiter_exceeded(self):
        """Test device operation rate limit exceeded."""
        from src.api.middleware.rate_limiter import DeviceOperationRateLimiter
        from fastapi import HTTPException
        from unittest.mock import AsyncMock
        
        rate_limiter = DeviceOperationRateLimiter()
        user_id = uuid4()
        
        # Mock Redis client returning high count
        mock_redis = AsyncMock()
        mock_redis.incr.return_value = 10  # Exceeds hourly limit of 5
        
        # Should raise rate limit exception
        with pytest.raises(HTTPException) as exc_info:
            await rate_limiter.check_device_operation_limit(
                user_id=user_id,
                operation="device_registration",
                redis_client=mock_redis
            )
        
        assert exc_info.value.status_code == 429
        assert "Hourly limit exceeded" in exc_info.value.detail
    
    def test_rate_limit_middleware_key_generation(self):
        """Test rate limit key generation."""
        from src.api.middleware.rate_limiter import RateLimitMiddleware
        from unittest.mock import Mock
        
        middleware = RateLimitMiddleware(None)
        
        # Test user-based key
        request = Mock()
        request.state.user = Mock()
        request.state.user.id = uuid4()
        
        key = asyncio.run(middleware._get_rate_limit_key(request))
        assert key.startswith("user:")
        
        # Test IP-based key
        request = Mock()
        request.state = Mock()
        request.client.host = "192.168.1.100"
        request.headers = {}
        
        key = asyncio.run(middleware._get_rate_limit_key(request))
        assert key == "ip:192.168.1.100"
    
    def test_rate_limit_middleware_endpoint_limits(self):
        """Test endpoint-specific rate limits."""
        from src.api.middleware.rate_limiter import RateLimitMiddleware
        
        middleware = RateLimitMiddleware(None)
        
        # Test device management limits
        limits = middleware._get_endpoint_limits("/api/v1/auth/device-management/overview")
        assert limits["requests_per_minute"] == 10
        
        # Test certificate limits
        limits = middleware._get_endpoint_limits("/api/v1/auth/certificates/enroll")
        assert limits["requests_per_minute"] == 5
        
        # Test default limits
        limits = middleware._get_endpoint_limits("/api/v1/some/other/endpoint")
        assert limits["requests_per_minute"] == 60
    
    def test_client_ip_extraction(self):
        """Test client IP extraction from headers."""
        from src.api.middleware.rate_limiter import RateLimitMiddleware
        from unittest.mock import Mock
        
        middleware = RateLimitMiddleware(None)
        
        # Test X-Forwarded-For header
        request = Mock()
        request.headers = {"X-Forwarded-For": "192.168.1.100, 10.0.0.1"}
        request.client = None
        
        ip = middleware._get_client_ip(request)
        assert ip == "192.168.1.100"
        
        # Test direct client
        request = Mock()
        request.headers = {}
        request.client = Mock()
        request.client.host = "192.168.1.200"
        
        ip = middleware._get_client_ip(request)
        assert ip == "192.168.1.200"
        
        # Test no IP available
        request = Mock()
        request.headers = {}
        request.client = None
        
        ip = middleware._get_client_ip(request)
        assert ip is None