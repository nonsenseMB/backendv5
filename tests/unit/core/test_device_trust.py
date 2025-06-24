"""
Unit tests for Device Trust system.
Tests trust scoring, level classification, and usage-based adjustments.
"""

import pytest
from uuid import UUID

from src.core.auth.device_trust import (
    calculate_trust_score,
    is_high_trust_device,
    is_medium_trust_device,
    is_low_trust_device,
    get_trust_level_name,
    should_require_additional_verification,
    get_session_timeout_minutes,
    get_max_session_duration_minutes,
    adjust_trust_score_for_usage,
    TRUSTED_AAGUIDS
)


class TestTrustScoreCalculation:
    """Test trust score calculation logic."""

    def test_calculate_trust_score_minimal(self):
        """Test trust score calculation with minimal parameters."""
        score = calculate_trust_score()

        # Base score only
        assert score == 10

    def test_calculate_trust_score_enterprise_attestation(self):
        """Test trust score with enterprise attestation."""
        score = calculate_trust_score(
            attestation_type="enterprise",
            authenticator_attachment="platform",
            user_verification=True
        )

        # Base(10) + Enterprise(40) + Platform(20) + UserVerification(10) = 80
        assert score == 80

    def test_calculate_trust_score_direct_attestation(self):
        """Test trust score with direct attestation."""
        score = calculate_trust_score(
            attestation_type="direct",
            authenticator_attachment="cross-platform",
            user_verification=True,
            is_resident_key=True
        )

        # Base(10) + Direct(30) + CrossPlatform(10) + UserVerification(10) + ResidentKey(5) = 65
        assert score == 65

    def test_calculate_trust_score_indirect_attestation(self):
        """Test trust score with indirect attestation."""
        score = calculate_trust_score(
            attestation_type="indirect",
            authenticator_attachment="platform"
        )

        # Base(10) + Indirect(20) + Platform(20) = 50
        assert score == 50

    def test_calculate_trust_score_none_attestation(self):
        """Test trust score with no attestation."""
        score = calculate_trust_score(
            attestation_type="none",
            authenticator_attachment="cross-platform"
        )

        # Base(10) + None(5) + CrossPlatform(10) = 25
        assert score == 25

    def test_calculate_trust_score_with_known_aaguid(self):
        """Test trust score with known trusted AAGUID."""
        # Windows Hello AAGUID
        windows_hello_aaguid = UUID("08987058-cadc-4b81-b6e1-30de50dcbe96")
        
        score = calculate_trust_score(
            attestation_type="direct",
            authenticator_attachment="platform",
            aaguid=windows_hello_aaguid,
            user_verification=True
        )

        # Base(10) + Direct(30) + Platform(20) + WindowsHello(20) + UserVerification(10) = 90
        assert score == 90

    def test_calculate_trust_score_with_yubikey(self):
        """Test trust score with YubiKey AAGUID."""
        yubikey_aaguid = UUID("ee882879-721c-4913-9775-3dfcce97072a")
        
        score = calculate_trust_score(
            attestation_type="direct",
            authenticator_attachment="cross-platform",
            aaguid=yubikey_aaguid,
            user_verification=True,
            is_resident_key=True
        )

        # Base(10) + Direct(30) + CrossPlatform(10) + YubiKey(35) + UserVerification(10) + ResidentKey(5) = 100
        assert score == 100

    def test_calculate_trust_score_unknown_aaguid(self):
        """Test trust score with unknown AAGUID."""
        unknown_aaguid = UUID("00000000-0000-0000-0000-000000000000")
        
        score = calculate_trust_score(
            attestation_type="direct",
            aaguid=unknown_aaguid
        )

        # Base(10) + Direct(30) = 40 (no bonus for unknown AAGUID)
        assert score == 40

    def test_calculate_trust_score_capped_at_100(self):
        """Test trust score is capped at 100."""
        # Use combination that would exceed 100
        yubikey_aaguid = UUID("ee882879-721c-4913-9775-3dfcce97072a")
        
        score = calculate_trust_score(
            attestation_type="enterprise",  # 40
            authenticator_attachment="platform",  # 20
            aaguid=yubikey_aaguid,  # 35
            user_verification=True,  # 10
            is_resident_key=True  # 5
        )
        # Total would be 120, but capped at 100
        assert score == 100

    def test_calculate_trust_score_no_user_verification(self):
        """Test trust score without user verification."""
        score = calculate_trust_score(
            attestation_type="direct",
            authenticator_attachment="platform",
            user_verification=False
        )

        # Base(10) + Direct(30) + Platform(20) = 60 (no UserVerification bonus)
        assert score == 60

    def test_calculate_trust_score_all_known_aaguids(self):
        """Test trust score calculation for all known AAGUIDs."""
        for aaguid_str, info in TRUSTED_AAGUIDS.items():
            aaguid = UUID(aaguid_str)
            
            score = calculate_trust_score(
                attestation_type="direct",
                aaguid=aaguid
            )
            
            # Base(10) + Direct(30) + TrustBonus = expected
            expected = 40 + info["trust_bonus"]
            assert score == min(expected, 100)


class TestTrustLevelClassification:
    """Test trust level classification functions."""

    def test_is_high_trust_device(self):
        """Test high trust device classification."""
        assert is_high_trust_device(100) is True
        assert is_high_trust_device(90) is True
        assert is_high_trust_device(80) is True
        assert is_high_trust_device(79) is False
        assert is_high_trust_device(50) is False
        assert is_high_trust_device(0) is False

    def test_is_medium_trust_device(self):
        """Test medium trust device classification."""
        assert is_medium_trust_device(79) is True
        assert is_medium_trust_device(65) is True
        assert is_medium_trust_device(50) is True
        assert is_medium_trust_device(80) is False
        assert is_medium_trust_device(49) is False
        assert is_medium_trust_device(0) is False

    def test_is_low_trust_device(self):
        """Test low trust device classification."""
        assert is_low_trust_device(49) is True
        assert is_low_trust_device(25) is True
        assert is_low_trust_device(0) is True
        assert is_low_trust_device(50) is False
        assert is_low_trust_device(80) is False
        assert is_low_trust_device(100) is False

    def test_get_trust_level_name(self):
        """Test trust level name generation."""
        assert get_trust_level_name(100) == "High"
        assert get_trust_level_name(90) == "High"
        assert get_trust_level_name(80) == "High"
        assert get_trust_level_name(79) == "Medium"
        assert get_trust_level_name(65) == "Medium"
        assert get_trust_level_name(50) == "Medium"
        assert get_trust_level_name(49) == "Low"
        assert get_trust_level_name(25) == "Low"
        assert get_trust_level_name(0) == "Low"

    def test_trust_level_boundaries(self):
        """Test trust level boundaries are consistent."""
        # Test boundary values
        boundary_tests = [
            (49, "Low"),
            (50, "Medium"),
            (79, "Medium"),
            (80, "High")
        ]
        
        for score, expected_level in boundary_tests:
            assert get_trust_level_name(score) == expected_level

    def test_should_require_additional_verification(self):
        """Test additional verification requirement logic."""
        # Low trust devices should require additional verification
        assert should_require_additional_verification(0) is True
        assert should_require_additional_verification(25) is True
        assert should_require_additional_verification(49) is True
        
        # Medium and high trust devices should not
        assert should_require_additional_verification(50) is False
        assert should_require_additional_verification(65) is False
        assert should_require_additional_verification(80) is False
        assert should_require_additional_verification(100) is False


class TestSessionTimeout:
    """Test session timeout calculation based on trust score."""

    def test_get_session_timeout_minutes_high_trust(self):
        """Test session timeout for high trust devices."""
        assert get_session_timeout_minutes(100) == 480  # 8 hours
        assert get_session_timeout_minutes(90) == 480
        assert get_session_timeout_minutes(80) == 480

    def test_get_session_timeout_minutes_medium_trust(self):
        """Test session timeout for medium trust devices."""
        assert get_session_timeout_minutes(79) == 120  # 2 hours
        assert get_session_timeout_minutes(65) == 120
        assert get_session_timeout_minutes(50) == 120

    def test_get_session_timeout_minutes_low_trust(self):
        """Test session timeout for low trust devices."""
        assert get_session_timeout_minutes(49) == 30  # 30 minutes
        assert get_session_timeout_minutes(25) == 30
        assert get_session_timeout_minutes(0) == 30

    def test_get_max_session_duration_minutes_high_trust(self):
        """Test maximum session duration for high trust devices."""
        assert get_max_session_duration_minutes(100) == 10080  # 7 days
        assert get_max_session_duration_minutes(90) == 10080
        assert get_max_session_duration_minutes(80) == 10080

    def test_get_max_session_duration_minutes_medium_trust(self):
        """Test maximum session duration for medium trust devices."""
        assert get_max_session_duration_minutes(79) == 1440  # 24 hours
        assert get_max_session_duration_minutes(65) == 1440
        assert get_max_session_duration_minutes(50) == 1440

    def test_get_max_session_duration_minutes_low_trust(self):
        """Test maximum session duration for low trust devices."""
        assert get_max_session_duration_minutes(49) == 480  # 8 hours
        assert get_max_session_duration_minutes(25) == 480
        assert get_max_session_duration_minutes(0) == 480

    def test_session_timeout_vs_max_duration_consistency(self):
        """Test that session timeout is always less than max duration."""
        test_scores = [0, 25, 49, 50, 65, 79, 80, 90, 100]
        
        for score in test_scores:
            timeout = get_session_timeout_minutes(score)
            max_duration = get_max_session_duration_minutes(score)
            assert timeout <= max_duration, f"Score {score}: timeout {timeout} > max_duration {max_duration}"


class TestUsageBasedAdjustment:
    """Test usage-based trust score adjustments."""

    def test_adjust_trust_score_no_adjustment(self):
        """Test trust score adjustment with no qualifying usage."""
        current_score = 50
        
        # Low usage, new device
        adjusted = adjust_trust_score_for_usage(
            current_score=current_score,
            use_count=5,
            days_since_registration=7,
            successful_auth_streak=3
        )
        
        assert adjusted == current_score

    def test_adjust_trust_score_high_usage_bonus(self):
        """Test trust score adjustment for high usage."""
        current_score = 50
        
        # High usage, mature device
        adjusted = adjust_trust_score_for_usage(
            current_score=current_score,
            use_count=60,
            days_since_registration=35,
            successful_auth_streak=25
        )
        
        # +10 for high usage + +5 for auth streak = +15
        assert adjusted == 65

    def test_adjust_trust_score_medium_usage_bonus(self):
        """Test trust score adjustment for medium usage."""
        current_score = 40
        
        # Medium usage
        adjusted = adjust_trust_score_for_usage(
            current_score=current_score,
            use_count=25,
            days_since_registration=20,
            successful_auth_streak=15
        )
        
        # +5 for medium usage + +3 for auth streak = +8
        assert adjusted == 48

    def test_adjust_trust_score_auth_streak_only(self):
        """Test trust score adjustment for auth streak only."""
        current_score = 60
        
        # Good auth streak but low usage
        adjusted = adjust_trust_score_for_usage(
            current_score=current_score,
            use_count=10,
            days_since_registration=5,
            successful_auth_streak=12
        )
        
        # +3 for auth streak only
        assert adjusted == 63

    def test_adjust_trust_score_high_auth_streak(self):
        """Test trust score adjustment for high auth streak."""
        current_score = 70
        
        # Very high auth streak
        adjusted = adjust_trust_score_for_usage(
            current_score=current_score,
            use_count=15,
            days_since_registration=10,
            successful_auth_streak=25
        )
        
        # +5 for high auth streak
        assert adjusted == 75

    def test_adjust_trust_score_capped_at_100(self):
        """Test trust score adjustment is capped at 100."""
        current_score = 95
        
        # Would exceed 100
        adjusted = adjust_trust_score_for_usage(
            current_score=current_score,
            use_count=60,
            days_since_registration=35,
            successful_auth_streak=25
        )
        
        # Should be capped at 100
        assert adjusted == 100

    def test_adjust_trust_score_exact_thresholds(self):
        """Test trust score adjustment at exact thresholds."""
        current_score = 50
        
        # Exact threshold for medium usage bonus
        adjusted = adjust_trust_score_for_usage(
            current_score=current_score,
            use_count=20,
            days_since_registration=14,
            successful_auth_streak=10
        )
        
        # +5 for medium usage + +3 for auth streak = +8
        assert adjusted == 58

    def test_adjust_trust_score_edge_cases(self):
        """Test trust score adjustment edge cases."""
        # Zero values
        adjusted = adjust_trust_score_for_usage(
            current_score=30,
            use_count=0,
            days_since_registration=0,
            successful_auth_streak=0
        )
        assert adjusted == 30

        # Very high values
        adjusted = adjust_trust_score_for_usage(
            current_score=20,
            use_count=1000,
            days_since_registration=365,
            successful_auth_streak=100
        )
        # +10 for high usage + +5 for high auth streak = +15
        assert adjusted == 35

    def test_adjust_trust_score_combinations(self):
        """Test various combinations of usage patterns."""
        test_cases = [
            # (current, use_count, days, streak, expected_bonus)
            (50, 51, 31, 21, 15),  # High usage + high streak
            (40, 21, 15, 11, 8),   # Medium usage + medium streak
            (60, 51, 31, 5, 10),   # High usage + low streak
            (30, 15, 25, 21, 5),   # Low usage + high streak
            (70, 51, 10, 0, 0),    # High usage but not enough days
            (80, 10, 50, 0, 0),    # Enough days but low usage
        ]
        
        for current, use_count, days, streak, expected_bonus in test_cases:
            adjusted = adjust_trust_score_for_usage(
                current_score=current,
                use_count=use_count,
                days_since_registration=days,
                successful_auth_streak=streak
            )
            assert adjusted == current + expected_bonus


class TestTrustedAAGUIDs:
    """Test trusted AAGUID configuration."""

    def test_trusted_aaguids_structure(self):
        """Test trusted AAGUIDs have correct structure."""
        for aaguid_str, info in TRUSTED_AAGUIDS.items():
            # Verify AAGUID format
            try:
                UUID(aaguid_str)
            except ValueError:
                pytest.fail(f"Invalid AAGUID format: {aaguid_str}")
            
            # Verify info structure
            assert "name" in info
            assert "trust_bonus" in info
            assert isinstance(info["name"], str)
            assert isinstance(info["trust_bonus"], int)
            assert info["trust_bonus"] > 0

    def test_trusted_aaguids_known_devices(self):
        """Test known trusted devices are present."""
        # Windows Hello
        assert "08987058-cadc-4b81-b6e1-30de50dcbe96" in TRUSTED_AAGUIDS
        assert "9ddd1817-af5a-4672-a2b9-3e3dd95000a9" in TRUSTED_AAGUIDS
        
        # Apple
        assert "dd4ec289-e01d-41c9-bb89-70fa845d4bf2" in TRUSTED_AAGUIDS
        
        # YubiKey
        assert "ee882879-721c-4913-9775-3dfcce97072a" in TRUSTED_AAGUIDS
        assert "fa2b99dc-9e39-4257-8f92-4a30d23c4118" in TRUSTED_AAGUIDS
        
        # Google Titan
        assert "0bb43545-fd2c-4185-87dd-feb0b2916ace" in TRUSTED_AAGUIDS

    def test_trusted_aaguids_trust_bonuses(self):
        """Test trust bonuses are reasonable."""
        for aaguid_str, info in TRUSTED_AAGUIDS.items():
            trust_bonus = info["trust_bonus"]
            # Trust bonuses should be reasonable (5-50)
            assert 5 <= trust_bonus <= 50, f"Trust bonus {trust_bonus} for {info['name']} is out of range"

    def test_trusted_aaguids_case_insensitive(self):
        """Test AAGUID lookup is case-insensitive."""
        # Should work with uppercase AAGUID
        uppercase_aaguid = UUID("08987058-CADC-4B81-B6E1-30DE50DCBE96")
        
        score = calculate_trust_score(
            attestation_type="direct",
            aaguid=uppercase_aaguid
        )
        
        # Should get the Windows Hello bonus
        assert score == 40 + 20  # Base + Direct + Windows Hello bonus


class TestTrustScoreConsistency:
    """Test trust score calculation consistency and edge cases."""

    def test_trust_score_deterministic(self):
        """Test trust score calculation is deterministic."""
        aaguid = UUID("ee882879-721c-4913-9775-3dfcce97072a")
        
        # Same inputs should produce same outputs
        score1 = calculate_trust_score(
            attestation_type="direct",
            authenticator_attachment="cross-platform",
            aaguid=aaguid,
            user_verification=True,
            is_resident_key=True
        )
        
        score2 = calculate_trust_score(
            attestation_type="direct",
            authenticator_attachment="cross-platform",
            aaguid=aaguid,
            user_verification=True,
            is_resident_key=True
        )
        
        assert score1 == score2

    def test_trust_score_parameter_order_independence(self):
        """Test trust score is independent of parameter order."""
        aaguid = UUID("08987058-cadc-4b81-b6e1-30de50dcbe96")
        
        # Different parameter orders should produce same result
        score1 = calculate_trust_score(
            attestation_type="direct",
            authenticator_attachment="platform",
            aaguid=aaguid,
            user_verification=True,
            is_resident_key=False
        )
        
        score2 = calculate_trust_score(
            user_verification=True,
            aaguid=aaguid,
            is_resident_key=False,
            attestation_type="direct",
            authenticator_attachment="platform"
        )
        
        assert score1 == score2

    def test_trust_score_none_values(self):
        """Test trust score calculation with None values."""
        score = calculate_trust_score(
            attestation_type=None,
            authenticator_attachment=None,
            aaguid=None,
            user_verification=False,
            is_resident_key=False
        )
        
        # Should only get base score
        assert score == 10

    def test_trust_score_incremental_build(self):
        """Test trust score builds incrementally."""
        base_score = calculate_trust_score()
        assert base_score == 10
        
        with_attestation = calculate_trust_score(attestation_type="direct")
        assert with_attestation == base_score + 30
        
        with_attachment = calculate_trust_score(
            attestation_type="direct",
            authenticator_attachment="platform"
        )
        assert with_attachment == base_score + 30 + 20
        
        with_verification = calculate_trust_score(
            attestation_type="direct",
            authenticator_attachment="platform",
            user_verification=True
        )
        assert with_verification == base_score + 30 + 20 + 10

    def test_invalid_attestation_type(self):
        """Test trust score with invalid attestation type."""
        score = calculate_trust_score(attestation_type="invalid")
        
        # Should only get base score (no attestation bonus)
        assert score == 10

    def test_invalid_authenticator_attachment(self):
        """Test trust score with invalid authenticator attachment."""
        score = calculate_trust_score(
            attestation_type="direct",
            authenticator_attachment="invalid"
        )
        
        # Should get base + direct attestation (no attachment bonus)
        assert score == 40