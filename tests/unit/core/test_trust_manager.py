"""Unit tests for device trust management."""
import pytest
from datetime import datetime, timedelta
from uuid import uuid4

from src.core.auth.trust_manager import DeviceTrustManager


class TestDeviceTrustManager:
    """Test device trust management functionality."""
    
    @pytest.fixture
    def trust_manager(self):
        """Create trust manager instance."""
        return DeviceTrustManager()
    
    def test_calculate_initial_trust_score_basic(self, trust_manager):
        """Test basic trust score calculation."""
        # Test with no attestation
        score, breakdown = trust_manager.calculate_initial_trust_score()
        assert score >= trust_manager.MIN_TRUST_SCORE
        assert breakdown["base_score"] == 10
        
        # Test with basic attestation
        score, breakdown = trust_manager.calculate_initial_trust_score(
            attestation_type="none",
            authenticator_attachment="cross-platform"
        )
        assert score == 25  # 10 base + 5 none + 10 cross-platform
        assert breakdown["attestation_bonus"] == 5
        assert breakdown["authenticator_bonus"] == 10
    
    def test_calculate_initial_trust_score_high_trust(self, trust_manager):
        """Test high trust device scoring."""
        # Known YubiKey with enterprise attestation
        aaguid = uuid4()
        trust_manager.TRUSTED_AAGUIDS[str(aaguid).lower()] = {
            "name": "Test YubiKey",
            "trust_bonus": 35
        }
        
        score, breakdown = trust_manager.calculate_initial_trust_score(
            attestation_type="enterprise",
            authenticator_attachment="platform",
            aaguid=aaguid,
            user_verification=True,
            is_resident_key=True,
            attestation_data={
                "is_enterprise": True,
                "has_hardware_backing": True,
                "has_secure_element": True
            }
        )
        
        # 10 base + 40 enterprise + 20 platform + 35 yubikey + 10 verification + 5 resident + 20 additional
        assert score == 100  # Capped at max
        assert breakdown["attestation_bonus"] == 40
        assert breakdown["authenticator_bonus"] == 20
        assert breakdown["known_device_bonus"] == 35
        assert breakdown["verification_bonus"] == 10
        assert breakdown["resident_key_bonus"] == 5
        assert breakdown["additional_factors"] == 20
    
    def test_calculate_trust_decay(self, trust_manager):
        """Test trust score decay over time."""
        current_time = datetime.utcnow()
        
        # No decay for recent usage
        score = trust_manager.calculate_trust_decay(
            current_score=80,
            last_used=current_time - timedelta(days=3),
            current_time=current_time
        )
        assert score == 80
        
        # 1 point decay per week
        score = trust_manager.calculate_trust_decay(
            current_score=80,
            last_used=current_time - timedelta(weeks=2),
            current_time=current_time
        )
        assert score == 78
        
        # Don't go below minimum
        score = trust_manager.calculate_trust_decay(
            current_score=15,
            last_used=current_time - timedelta(weeks=52),
            current_time=current_time
        )
        assert score == trust_manager.MIN_TRUST_SCORE
    
    def test_adjust_trust_for_behavior_positive(self, trust_manager):
        """Test positive trust adjustments."""
        analytics = {
            "successful_auth_streak": 50,
            "days_active_last_month": 25,
            "location_consistency": 0.95,
            "failed_auth_attempts": 0,
            "suspicious_activity_count": 0,
            "unusual_time_access": 0
        }
        
        score, reasons = trust_manager.adjust_trust_for_behavior(50, analytics)
        # 50 + 10 (streak) + 5 (regular usage) + 3 (location) = 68
        assert score == 68
        assert len(reasons) == 3
        assert "Excellent authentication streak" in reasons[0]
    
    def test_adjust_trust_for_behavior_negative(self, trust_manager):
        """Test negative trust adjustments."""
        analytics = {
            "successful_auth_streak": 0,
            "failed_auth_attempts": 10,
            "suspicious_activity_count": 2,
            "unusual_time_access": 5,
            "location_consistency": 0.3
        }
        
        score, reasons = trust_manager.adjust_trust_for_behavior(70, analytics)
        # 70 - 10 (failed auth) - 20 (suspicious) - 5 (unusual times) = 35
        assert score == 35
        assert len(reasons) == 3
        assert "Multiple failed authentications" in reasons[0]
    
    def test_get_device_policy(self, trust_manager):
        """Test policy retrieval based on trust score."""
        # High trust
        policy = trust_manager.get_device_policy(85)
        assert policy["trust_level"] == "high"
        assert policy["trust_level_name"] == "High"
        assert policy["allow_sensitive_operations"] is True
        assert policy["require_mfa"] is False
        
        # Medium trust
        policy = trust_manager.get_device_policy(60)
        assert policy["trust_level"] == "medium"
        assert policy["allow_sensitive_operations"] is False
        assert policy["require_mfa"] is True
        
        # Low trust
        policy = trust_manager.get_device_policy(30)
        assert policy["trust_level"] == "low"
        assert policy["session_timeout_minutes"] == 30
        
        # Very low trust
        policy = trust_manager.get_device_policy(20)
        assert policy["trust_level"] == "low"
        assert policy["session_timeout_minutes"] == 15
        assert policy.get("require_continuous_verification") is True
    
    def test_should_trigger_trust_review(self, trust_manager):
        """Test trust review triggers."""
        device_id = uuid4()
        
        # No previous review
        should_review, reasons = trust_manager.should_trigger_trust_review(
            device_id=device_id,
            trust_score=50,
            last_review=None
        )
        assert should_review is True
        assert "No previous review" in reasons
        
        # Time-based review
        should_review, reasons = trust_manager.should_trigger_trust_review(
            device_id=device_id,
            trust_score=50,
            last_review=datetime.utcnow() - timedelta(days=100)
        )
        assert should_review is True
        assert "Quarterly review due" in reasons
        
        # Analytics-based triggers
        should_review, reasons = trust_manager.should_trigger_trust_review(
            device_id=device_id,
            trust_score=50,
            last_review=datetime.utcnow() - timedelta(days=10),
            analytics={
                "failed_auth_attempts": 5,
                "location_changes": 10,
                "unusual_activity_score": 0.8
            }
        )
        assert should_review is True
        assert len(reasons) == 3
    
    def test_record_device_event(self, trust_manager):
        """Test device event recording."""
        device_id = uuid4()
        
        # Record authentication event
        trust_manager.record_device_event(
            device_id=device_id,
            event_type="authentication",
            success=True
        )
        
        analytics = trust_manager.get_device_analytics(device_id)
        assert analytics["successful_auth_count"] == 1
        assert analytics["successful_auth_streak"] == 1
        assert analytics["has_analytics"] is True
        
        # Record failed auth
        trust_manager.record_device_event(
            device_id=device_id,
            event_type="authentication",
            success=False
        )
        
        analytics = trust_manager.get_device_analytics(device_id)
        assert analytics["failed_auth_count"] == 1
        assert analytics["successful_auth_streak"] == 0
        assert analytics["success_rate"] == 0.5
    
    def test_generate_trust_report(self, trust_manager):
        """Test trust report generation."""
        device_id = uuid4()
        
        # Add some analytics
        trust_manager.record_device_event(
            device_id=device_id,
            event_type="authentication",
            success=False
        )
        trust_manager.record_device_event(
            device_id=device_id,
            event_type="authentication",
            success=False
        )
        trust_manager.record_device_event(
            device_id=device_id,
            event_type="authentication",
            success=False
        )
        trust_manager.record_device_event(
            device_id=device_id,
            event_type="authentication",
            success=False
        )
        
        device_info = {
            "device_name": "Test Device",
            "device_type": "webauthn",
            "created_at": datetime.utcnow().isoformat(),
            "last_used": datetime.utcnow().isoformat()
        }
        
        report = trust_manager.generate_trust_report(
            device_id=device_id,
            trust_score=45,
            device_info=device_info
        )
        
        assert report["device_id"] == str(device_id)
        assert report["trust_score"] == 45
        assert report["trust_level"] == "Low"
        assert len(report["recommendations"]) >= 2
        assert "Consider re-authenticating" in report["recommendations"][0]
        assert "Review failed authentication" in report["recommendations"][1]
    
    def test_analytics_cache_isolation(self, trust_manager):
        """Test that device analytics are isolated."""
        device1 = uuid4()
        device2 = uuid4()
        
        # Record events for device 1
        trust_manager.record_device_event(
            device_id=device1,
            event_type="authentication",
            success=True
        )
        
        # Record events for device 2
        trust_manager.record_device_event(
            device_id=device2,
            event_type="authentication",
            success=False
        )
        
        # Check isolation
        analytics1 = trust_manager.get_device_analytics(device1)
        analytics2 = trust_manager.get_device_analytics(device2)
        
        assert analytics1["successful_auth_count"] == 1
        assert analytics1["failed_auth_count"] == 0
        
        assert analytics2["successful_auth_count"] == 0
        assert analytics2["failed_auth_count"] == 1