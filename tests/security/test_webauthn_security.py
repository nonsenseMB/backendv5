"""Security tests for WebAuthn implementation."""
import base64
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from src.api.v1.auth.validators import WebAuthnValidator
from src.infrastructure.auth.challenge_store import ChallengeStore, InMemoryChallengeStore
from src.infrastructure.auth.credential_validator import CredentialValidator
from src.infrastructure.auth.webauthn_manager import VerificationResult, WebAuthnManager


class TestReplayAttackPrevention:
    """Test protection against replay attacks."""
    
    @pytest.mark.asyncio
    async def test_challenge_cannot_be_reused(self):
        """Test that challenges cannot be reused."""
        store = InMemoryChallengeStore()
        user_id = str(uuid4())
        challenge = "test-challenge-replay"
        
        # Store challenge
        await store.store_challenge(user_id, challenge, "authentication")
        
        # First retrieval should succeed
        retrieved1 = await store.retrieve_challenge(user_id, "authentication")
        assert retrieved1 == challenge
        
        # Second retrieval should fail (challenge consumed)
        retrieved2 = await store.retrieve_challenge(user_id, "authentication")
        assert retrieved2 is None
        
        # Storing the same challenge again should work
        await store.store_challenge(user_id, challenge, "authentication")
        
        # But it's a new instance, so retrieval works once
        retrieved3 = await store.retrieve_challenge(user_id, "authentication")
        assert retrieved3 == challenge
    
    @pytest.mark.asyncio
    async def test_sign_counter_prevents_replay(self):
        """Test that sign counter validation prevents replay attacks."""
        # Test cases for counter validation
        test_cases = [
            # (new_counter, stored_counter, allow_zero, expected_result)
            (5, 4, False, True),    # Valid increment
            (10, 5, False, True),   # Valid large increment
            (5, 5, False, False),   # Same counter (replay)
            (4, 5, False, False),   # Decreased counter (replay)
            (0, 0, True, True),     # Zero counters allowed
            (0, 0, False, False),   # Zero counters not allowed
            (1, 0, False, True),    # First increment from zero
        ]
        
        for new_counter, stored_counter, allow_zero, expected in test_cases:
            result = CredentialValidator.validate_counter(
                new_counter, stored_counter, allow_zero
            )
            assert result == expected, (
                f"Counter validation failed for new={new_counter}, "
                f"stored={stored_counter}, allow_zero={allow_zero}"
            )
    
    @pytest.mark.asyncio
    async def test_authentication_with_old_counter_fails(self):
        """Test that authentication with old counter value fails."""
        manager = WebAuthnManager()
        
        # Create mock verification data
        mock_credential = MagicMock()
        mock_credential.id = "test-credential"
        mock_credential.response.client_data_json = base64.b64encode(
            json.dumps({
                "type": "webauthn.get",
                "challenge": "test-challenge",
                "origin": "https://localhost"
            }).encode()
        ).decode()
        mock_credential.response.authenticator_data = base64.b64encode(
            b"\x00" * 32 +  # RP ID hash
            b"\x05" +       # Flags (UP=1, UV=1)
            b"\x00\x00\x00\x05"  # Counter = 5
        ).decode()
        mock_credential.response.signature = "fake-signature"
        
        # Mock the signature verification to focus on counter validation
        with patch.object(CredentialValidator, 'verify_signature', return_value=True):
            # First authentication with counter 10 (stored)
            result = await manager.verify_authentication(
                credential=mock_credential,
                challenge="test-challenge",
                public_key="fake-public-key",
                sign_count=10  # Stored counter is 10
            )
            
            # Should fail because new counter (5) < stored counter (10)
            assert result.verified is False
            assert "counter" in result.error.lower()


class TestChallengeSecurityy:
    """Test challenge generation and validation security."""
    
    @pytest.mark.asyncio
    async def test_challenge_uniqueness(self):
        """Test that generated challenges are unique."""
        manager = WebAuthnManager()
        challenges = set()
        
        # Generate 100 challenges
        for _ in range(100):
            options = await manager.generate_registration_options(
                user_id="test-user",
                user_name="test@example.com",
                user_display_name="Test User"
            )
            challenges.add(options.challenge)
        
        # All should be unique
        assert len(challenges) == 100
    
    @pytest.mark.asyncio
    async def test_challenge_entropy(self):
        """Test that challenges have sufficient entropy."""
        manager = WebAuthnManager()
        
        options = await manager.generate_registration_options(
            user_id="test-user",
            user_name="test@example.com",
            user_display_name="Test User"
        )
        
        # Decode challenge
        challenge_bytes = base64.urlsafe_b64decode(options.challenge + "===")
        
        # Should be 32 bytes (256 bits) of entropy
        assert len(challenge_bytes) == 32
        
        # Should not be all zeros or a simple pattern
        assert challenge_bytes != b"\x00" * 32
        assert challenge_bytes != b"\xff" * 32
        assert challenge_bytes != b"\x01\x02\x03\x04" * 8
    
    @pytest.mark.asyncio
    async def test_challenge_expiry(self):
        """Test that challenges expire after TTL."""
        store = InMemoryChallengeStore()
        store.ttl = 1  # 1 second TTL for testing
        
        user_id = str(uuid4())
        challenge = "test-expiry"
        
        # Store challenge
        await store.store_challenge(user_id, challenge, "registration")
        
        # Immediate retrieval should work
        retrieved = await store.retrieve_challenge(user_id, "registration")
        assert retrieved == challenge
        
        # Store again
        await store.store_challenge(user_id, challenge, "registration")
        
        # Wait for expiry
        time.sleep(1.5)
        
        # Should be expired
        retrieved = await store.retrieve_challenge(user_id, "registration")
        assert retrieved is None


class TestOriginValidation:
    """Test origin validation to prevent cross-origin attacks."""
    
    def test_origin_validation_strict(self):
        """Test strict origin validation."""
        valid_origins = [
            "https://example.com",
            "https://app.example.com",
            "https://localhost:3000"
        ]
        
        # Valid cases
        assert WebAuthnValidator.validate_origin("https://example.com", valid_origins)
        assert WebAuthnValidator.validate_origin("https://app.example.com", valid_origins)
        assert WebAuthnValidator.validate_origin("https://localhost:3000", valid_origins)
        
        # Invalid cases
        assert not WebAuthnValidator.validate_origin("https://evil.com", valid_origins)
        assert not WebAuthnValidator.validate_origin("http://example.com", valid_origins)  # Wrong protocol
        assert not WebAuthnValidator.validate_origin("https://example.com.evil.com", valid_origins)
        assert not WebAuthnValidator.validate_origin("https://example.com:8080", valid_origins)  # Wrong port
    
    def test_origin_normalization(self):
        """Test that origins are properly normalized."""
        valid_origins = ["https://example.com/", "https://app.example.com"]
        
        # Trailing slashes should be normalized
        assert WebAuthnValidator.validate_origin("https://example.com", valid_origins)
        assert WebAuthnValidator.validate_origin("https://example.com/", valid_origins)


class TestCredentialValidation:
    """Test credential validation security."""
    
    def test_credential_id_validation(self):
        """Test credential ID validation."""
        # Valid credential IDs
        valid_id = base64.b64encode(b"valid-credential-id").decode()
        assert WebAuthnValidator.validate_credential_id(valid_id)
        
        # Empty credential ID
        assert not WebAuthnValidator.validate_credential_id("")
        
        # Invalid base64
        assert not WebAuthnValidator.validate_credential_id("not-base64!")
        
        # Too long (over 1023 bytes)
        long_id = base64.b64encode(b"x" * 1024).decode()
        assert not WebAuthnValidator.validate_credential_id(long_id)
    
    def test_rp_id_validation(self):
        """Test Relying Party ID validation."""
        # Valid RP IDs
        assert WebAuthnValidator.validate_rp_id("example.com")
        assert WebAuthnValidator.validate_rp_id("app.example.com")
        assert WebAuthnValidator.validate_rp_id("localhost")
        assert WebAuthnValidator.validate_rp_id("example.co.uk")
        
        # Invalid RP IDs
        assert not WebAuthnValidator.validate_rp_id("")
        assert not WebAuthnValidator.validate_rp_id("https://example.com")  # No protocol
        assert not WebAuthnValidator.validate_rp_id("example.com/path")  # No path
        assert not WebAuthnValidator.validate_rp_id("example")  # No TLD (except localhost)
        assert not WebAuthnValidator.validate_rp_id("a" * 254)  # Too long


class TestUserVerification:
    """Test user verification requirements."""
    
    def test_user_verification_enforcement(self):
        """Test that user verification is properly enforced."""
        # Create authenticator data with different flag combinations
        # Flags byte structure:
        # bit 0: User Present (UP)
        # bit 2: User Verified (UV)
        # bit 6: Attested credential data (AT)
        # bit 7: Extension data (ED)
        
        auth_data_base = bytearray(37)  # Minimum authenticator data size
        
        # Test different flag combinations
        test_cases = [
            (0x01, "required", False),  # UP only, UV required -> fail
            (0x05, "required", True),   # UP + UV, UV required -> pass
            (0x01, "preferred", True),  # UP only, UV preferred -> pass
            (0x05, "preferred", True),  # UP + UV, UV preferred -> pass
            (0x01, "discouraged", True),# UP only, UV discouraged -> pass
            (0x00, "required", False),  # No UP, UV required -> fail
        ]
        
        for flags, requirement, expected in test_cases:
            auth_data = auth_data_base.copy()
            auth_data[32] = flags
            
            result = WebAuthnValidator.validate_user_verification(
                bytes(auth_data), requirement
            )
            assert result == expected, (
                f"User verification failed for flags={flags:02x}, "
                f"requirement={requirement}"
            )


class TestAttestationSecurity:
    """Test attestation verification security."""
    
    def test_attestation_types(self):
        """Test different attestation types are handled correctly."""
        # Test attestation type validation
        valid_types = ["none", "indirect", "direct", "enterprise"]
        
        for att_type in valid_types:
            assert WebAuthnValidator.validate_attestation_type(att_type)
        
        # Invalid types
        assert not WebAuthnValidator.validate_attestation_type("invalid")
        assert not WebAuthnValidator.validate_attestation_type("")
        assert not WebAuthnValidator.validate_attestation_type(None)
    
    @pytest.mark.asyncio
    async def test_self_attestation_accepted(self):
        """Test that self-attestation is properly handled."""
        # Self-attestation should be accepted but marked appropriately
        verified, att_type = CredentialValidator.verify_attestation(
            fmt="none",
            att_stmt={},
            auth_data=b"mock-auth-data",
            client_data_hash=b"mock-client-data-hash"
        )
        
        assert verified is True
        assert att_type == "none"
    
    @pytest.mark.asyncio
    async def test_packed_attestation_validation(self):
        """Test packed attestation format validation."""
        # Test with missing signature
        verified, att_type = CredentialValidator._verify_packed_attestation(
            att_stmt={"alg": -7},  # No signature
            auth_data=b"mock-auth-data",
            client_data_hash=b"mock-client-data-hash"
        )
        
        assert verified is False
        assert att_type is None


class TestInputSanitization:
    """Test input sanitization and validation."""
    
    def test_client_data_json_validation(self):
        """Test client data JSON validation."""
        # Valid client data
        valid_data = {
            "type": "webauthn.create",
            "challenge": "test-challenge",
            "origin": "https://example.com"
        }
        valid_json = base64.b64encode(json.dumps(valid_data).encode()).decode()
        
        parsed = WebAuthnValidator.validate_client_data_json(valid_json)
        assert parsed["type"] == "webauthn.create"
        assert parsed["challenge"] == "test-challenge"
        
        # Missing required field
        invalid_data = {
            "type": "webauthn.create",
            "challenge": "test-challenge"
            # Missing origin
        }
        invalid_json = base64.b64encode(json.dumps(invalid_data).encode()).decode()
        
        with pytest.raises(ValueError, match="Missing required field"):
            WebAuthnValidator.validate_client_data_json(invalid_json)
        
        # Invalid JSON
        invalid_json = base64.b64encode(b"not-json").decode()
        with pytest.raises(ValueError, match="Invalid JSON"):
            WebAuthnValidator.validate_client_data_json(invalid_json)
        
        # Invalid base64
        with pytest.raises(ValueError, match="Invalid base64"):
            WebAuthnValidator.validate_client_data_json("not-base64!")
    
    def test_base64_validation(self):
        """Test base64 validation and padding handling."""
        # Valid base64 with different padding scenarios
        test_cases = [
            ("dGVzdA==", b"test"),      # Standard padding
            ("dGVzdA", b"test"),        # Missing padding
            ("dGVzdDE=", b"test1"),     # One padding
            ("dGVzdDEy", b"test12"),    # No padding needed
        ]
        
        for encoded, expected in test_cases:
            decoded = WebAuthnValidator.validate_base64(encoded, "test")
            assert decoded == expected
        
        # Invalid base64
        with pytest.raises(ValueError):
            WebAuthnValidator.validate_base64("invalid!@#", "test")