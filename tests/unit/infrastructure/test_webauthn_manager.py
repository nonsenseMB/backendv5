"""
Unit tests for WebAuthn Manager.
Tests WebAuthn registration and authentication flows.
"""

import base64
import secrets
from unittest.mock import Mock, patch, AsyncMock
from uuid import uuid4, UUID

import pytest
import cbor2

from src.infrastructure.auth.webauthn_manager import WebAuthnManager, VerificationResult
from src.api.v1.auth.schemas import (
    DeviceRegistrationOptions,
    DeviceRegistrationVerification,
    AuthenticationOptions, 
    DeviceAuthenticationVerification,
    DeviceRegistrationResponse,
    DeviceAuthenticationResponse
)


class TestWebAuthnManager:
    """Test WebAuthn Manager functionality."""

    @pytest.fixture
    def webauthn_manager(self):
        """Create WebAuthn manager instance."""
        with patch('src.infrastructure.auth.webauthn_manager.settings') as mock_settings:
            mock_settings.WEBAUTHN_RP_ID = "example.com"
            mock_settings.WEBAUTHN_RP_NAME = "Test App"
            mock_settings.WEBAUTHN_RP_ICON = None
            mock_settings.WEBAUTHN_USER_VERIFICATION = "required"
            mock_settings.WEBAUTHN_ATTESTATION = "direct"
            mock_settings.WEBAUTHN_TIMEOUT = 60000
            mock_settings.APP_DOMAIN = "example.com"
            mock_settings.APP_NAME = "Test App"
            mock_settings.APP_ENV = "test"
            mock_settings.CORS_ORIGINS = ["https://example.com"]
            return WebAuthnManager()

    @pytest.fixture
    def test_user_data(self):
        """Test user data."""
        return {
            "user_id": str(uuid4()),
            "user_name": "test@example.com",
            "user_display_name": "Test User"
        }

    def test_initialization(self, webauthn_manager):
        """Test WebAuthn manager initialization."""
        assert webauthn_manager.rp_id == "example.com"
        assert webauthn_manager.rp_name == "Test App"
        assert webauthn_manager.user_verification == "required"
        assert webauthn_manager.attestation == "direct"
        assert webauthn_manager.timeout == 60000
        assert "https://example.com" in webauthn_manager.allowed_origins

    def test_get_allowed_origins_development(self):
        """Test allowed origins in development mode."""
        with patch('src.infrastructure.auth.webauthn_manager.settings') as mock_settings:
            mock_settings.APP_DOMAIN = "localhost"
            mock_settings.APP_ENV = "development"
            mock_settings.CORS_ORIGINS = ["https://localhost:3000"]
            manager = WebAuthnManager()
            
            origins = manager.allowed_origins
            assert "https://localhost" in origins
            assert "http://localhost" in origins
            assert "http://localhost:3000" in origins
            assert "http://localhost:8000" in origins

    def test_get_allowed_origins_production(self):
        """Test allowed origins in production mode."""
        with patch('src.infrastructure.auth.webauthn_manager.settings') as mock_settings:
            mock_settings.APP_DOMAIN = "example.com"
            mock_settings.APP_ENV = "production"
            mock_settings.CORS_ORIGINS = ["https://example.com"]
            manager = WebAuthnManager()
            
            origins = manager.allowed_origins
            assert "https://example.com" in origins
            assert "http://example.com" not in origins

    async def test_generate_registration_options(self, webauthn_manager, test_user_data):
        """Test generating registration options."""
        options = await webauthn_manager.generate_registration_options(
            user_id=test_user_data["user_id"],
            user_name=test_user_data["user_name"],
            user_display_name=test_user_data["user_display_name"]
        )

        assert isinstance(options, DeviceRegistrationOptions)
        assert options.rp_id == "example.com"
        assert options.rp_name == "Test App"
        assert options.user_name == test_user_data["user_name"]
        assert options.user_display_name == test_user_data["user_display_name"]
        assert options.attestation == "direct"
        assert options.timeout == 60000
        assert len(options.challenge) > 0
        assert len(options.user_id) > 0

        # Check authenticator selection
        auth_selection = options.authenticator_selection
        assert auth_selection["authenticatorAttachment"] == "platform"
        assert auth_selection["residentKey"] == "preferred"
        assert auth_selection["userVerification"] == "required"

    async def test_generate_registration_options_with_exclude_credentials(
        self, webauthn_manager, test_user_data
    ):
        """Test generating registration options with exclude credentials."""
        exclude_credentials = [
            {"id": "cred1", "type": "public-key"},
            {"id": "cred2", "type": "public-key"}
        ]

        options = await webauthn_manager.generate_registration_options(
            user_id=test_user_data["user_id"],
            user_name=test_user_data["user_name"],
            user_display_name=test_user_data["user_display_name"],
            exclude_credentials=exclude_credentials
        )

        assert options.exclude_credentials == exclude_credentials

    async def test_generate_registration_options_error_handling(self, webauthn_manager):
        """Test error handling in registration options generation."""
        with pytest.raises(Exception):
            await webauthn_manager.generate_registration_options(
                user_id="",  # Invalid user ID
                user_name="",
                user_display_name=""
            )

    async def test_generate_authentication_options(self, webauthn_manager):
        """Test generating authentication options."""
        allow_credentials = [
            {"id": "cred1", "type": "public-key"},
            {"id": "cred2", "type": "public-key"}
        ]

        options = await webauthn_manager.generate_authentication_options(
            allow_credentials=allow_credentials
        )

        assert isinstance(options, AuthenticationOptions)
        assert options.rp_id == "example.com"
        assert options.user_verification == "required"
        assert options.timeout == 60000
        assert options.allow_credentials == allow_credentials
        assert len(options.challenge) > 0

    async def test_generate_authentication_options_empty_credentials(self, webauthn_manager):
        """Test generating authentication options with empty credentials."""
        options = await webauthn_manager.generate_authentication_options(
            allow_credentials=[]
        )

        assert options.allow_credentials == []

    def test_generate_device_name(self, webauthn_manager):
        """Test device name generation from user agent."""
        test_cases = [
            {
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "expected": "Chrome on Windows"
            },
            {
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
                "expected": "Safari on macOS"
            },
            {
                "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "expected": "Chrome on Linux"
            },
            {
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
                "expected": "Firefox on Windows"
            },
            {
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
                "expected": "Edge on Windows"
            },
            {
                "user_agent": "",
                "expected": "Unknown Device"
            }
        ]

        for case in test_cases:
            result = webauthn_manager.generate_device_name(case["user_agent"])
            assert result == case["expected"]

    def test_extract_browser(self, webauthn_manager):
        """Test browser extraction from user agent."""
        assert webauthn_manager.extract_browser("Chrome/91.0") == "Chrome"
        assert webauthn_manager.extract_browser("Firefox/89.0") == "Firefox"
        assert webauthn_manager.extract_browser("Safari/605.1.15") == "Safari"
        assert webauthn_manager.extract_browser("Edg/91.0") == "Edge"
        assert webauthn_manager.extract_browser("Unknown") == "Browser"

    def test_extract_platform(self, webauthn_manager):
        """Test platform extraction from user agent."""
        assert webauthn_manager.extract_platform("Windows NT 10.0") == "Windows"
        assert webauthn_manager.extract_platform("Macintosh; Intel Mac OS X") == "macOS"
        assert webauthn_manager.extract_platform("X11; Linux x86_64") == "Linux"
        assert webauthn_manager.extract_platform("Android 11") == "Android"
        assert webauthn_manager.extract_platform("iPhone OS 14_6") == "iOS"
        assert webauthn_manager.extract_platform("iPad OS 14_6") == "iOS"
        assert webauthn_manager.extract_platform("Unknown") == "Unknown"


class TestWebAuthnVerification:
    """Test WebAuthn verification functionality."""

    @pytest.fixture
    def webauthn_manager(self):
        """Create WebAuthn manager with mocked settings."""
        with patch('src.infrastructure.auth.webauthn_manager.settings') as mock_settings:
            mock_settings.WEBAUTHN_RP_ID = "example.com"
            mock_settings.WEBAUTHN_RP_NAME = "Test App"
            mock_settings.WEBAUTHN_USER_VERIFICATION = "required"
            mock_settings.WEBAUTHN_ATTESTATION = "direct"
            mock_settings.WEBAUTHN_TIMEOUT = 60000
            mock_settings.APP_DOMAIN = "example.com"
            mock_settings.CORS_ORIGINS = ["https://example.com"]
            mock_settings.APP_ENV = "test"
            return WebAuthnManager()

    @pytest.fixture
    def mock_credential_validator(self):
        """Mock credential validator."""
        with patch('src.infrastructure.auth.webauthn_manager.CredentialValidator') as mock:
            yield mock

    @pytest.fixture
    def mock_webauthn_validator(self):
        """Mock WebAuthn validator."""
        with patch('src.infrastructure.auth.webauthn_manager.WebAuthnValidator') as mock:
            yield mock

    @pytest.fixture
    def valid_client_data(self):
        """Valid client data for testing."""
        return {
            "type": "webauthn.create",
            "challenge": "test-challenge",
            "origin": "https://example.com"
        }

    @pytest.fixture
    def valid_registration_credential(self):
        """Valid registration credential for testing."""
        return DeviceRegistrationVerification(
            id="test-credential-id",
            raw_id="test-raw-id",
            response=DeviceRegistrationResponse(
                client_data_json="eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
                attestation_object="o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikU2pOKzNs"
            ),
            type="public-key"
        )

    async def test_verify_registration_success(
        self, webauthn_manager, mock_webauthn_validator, mock_credential_validator,
        valid_client_data, valid_registration_credential
    ):
        """Test successful registration verification."""
        # Setup mocks
        mock_webauthn_validator.validate_client_data_json.return_value = valid_client_data
        mock_webauthn_validator.validate_challenge.return_value = True
        mock_webauthn_validator.validate_origin.return_value = True
        mock_webauthn_validator.validate_base64.return_value = b"mock_data"

        mock_attestation = {
            "fmt": "none",
            "authData": b"mock_auth_data",
            "attStmt": {},
            "parsedAuthData": {
                "credentialPublicKey": {"1": 2, "3": -7},
                "signCount": 0,
                "aaguid": b"\x00" * 16,
                "flags": {"up": True, "uv": True}
            }
        }
        mock_credential_validator.parse_attestation_object.return_value = mock_attestation
        mock_credential_validator.verify_attestation.return_value = (True, "none")
        mock_credential_validator.extract_public_key_from_cose.return_value = "mock-public-key"

        result = await webauthn_manager.verify_registration(
            credential=valid_registration_credential,
            challenge="test-challenge",
            user_id="test-user"
        )

        assert isinstance(result, VerificationResult)
        assert result.verified is True
        assert result.public_key == "mock-public-key"
        assert result.sign_count == 0
        assert result.attestation_type == "none"
        assert result.error is None

    async def test_verify_registration_invalid_client_data_type(
        self, webauthn_manager, mock_webauthn_validator, valid_registration_credential
    ):
        """Test registration verification with invalid client data type."""
        invalid_client_data = {
            "type": "webauthn.get",  # Wrong type
            "challenge": "test-challenge",
            "origin": "https://example.com"
        }
        mock_webauthn_validator.validate_client_data_json.return_value = invalid_client_data

        result = await webauthn_manager.verify_registration(
            credential=valid_registration_credential,
            challenge="test-challenge",
            user_id="test-user"
        )

        assert result.verified is False
        assert result.error == "Invalid client data type"

    async def test_verify_registration_challenge_mismatch(
        self, webauthn_manager, mock_webauthn_validator, valid_registration_credential,
        valid_client_data
    ):
        """Test registration verification with challenge mismatch."""
        mock_webauthn_validator.validate_client_data_json.return_value = valid_client_data
        mock_webauthn_validator.validate_challenge.return_value = False

        result = await webauthn_manager.verify_registration(
            credential=valid_registration_credential,
            challenge="different-challenge",
            user_id="test-user"
        )

        assert result.verified is False
        assert result.error == "Challenge mismatch"

    async def test_verify_registration_invalid_origin(
        self, webauthn_manager, mock_webauthn_validator, valid_registration_credential,
        valid_client_data
    ):
        """Test registration verification with invalid origin."""
        mock_webauthn_validator.validate_client_data_json.return_value = valid_client_data
        mock_webauthn_validator.validate_challenge.return_value = True
        mock_webauthn_validator.validate_origin.return_value = False

        result = await webauthn_manager.verify_registration(
            credential=valid_registration_credential,
            challenge="test-challenge",
            user_id="test-user"
        )

        assert result.verified is False
        assert result.error == "Invalid origin"

    async def test_verify_registration_attestation_verification_failed(
        self, webauthn_manager, mock_webauthn_validator, mock_credential_validator,
        valid_client_data, valid_registration_credential
    ):
        """Test registration verification with failed attestation."""
        # Setup valid client data validation
        mock_webauthn_validator.validate_client_data_json.return_value = valid_client_data
        mock_webauthn_validator.validate_challenge.return_value = True
        mock_webauthn_validator.validate_origin.return_value = True
        mock_webauthn_validator.validate_base64.return_value = b"mock_data"

        # Setup failed attestation verification
        mock_attestation = {
            "fmt": "packed",
            "authData": b"mock_auth_data",
            "attStmt": {},
            "parsedAuthData": {}
        }
        mock_credential_validator.parse_attestation_object.return_value = mock_attestation
        mock_credential_validator.verify_attestation.return_value = (False, None)

        result = await webauthn_manager.verify_registration(
            credential=valid_registration_credential,
            challenge="test-challenge",
            user_id="test-user"
        )

        assert result.verified is False
        assert result.error == "Attestation verification failed"

    async def test_verify_registration_missing_public_key(
        self, webauthn_manager, mock_webauthn_validator, mock_credential_validator,
        valid_client_data, valid_registration_credential
    ):
        """Test registration verification with missing public key."""
        # Setup valid validation up to public key extraction
        mock_webauthn_validator.validate_client_data_json.return_value = valid_client_data
        mock_webauthn_validator.validate_challenge.return_value = True
        mock_webauthn_validator.validate_origin.return_value = True
        mock_webauthn_validator.validate_base64.return_value = b"mock_data"

        mock_attestation = {
            "fmt": "none",
            "authData": b"mock_auth_data",
            "attStmt": {},
            "parsedAuthData": {}  # No credentialPublicKey
        }
        mock_credential_validator.parse_attestation_object.return_value = mock_attestation
        mock_credential_validator.verify_attestation.return_value = (True, "none")

        result = await webauthn_manager.verify_registration(
            credential=valid_registration_credential,
            challenge="test-challenge",
            user_id="test-user"
        )

        assert result.verified is False
        assert result.error == "No public key in attestation"

    async def test_verify_registration_exception_handling(
        self, webauthn_manager, mock_webauthn_validator, valid_registration_credential
    ):
        """Test registration verification exception handling."""
        # Setup mock to raise exception
        mock_webauthn_validator.validate_client_data_json.side_effect = Exception("Test error")

        result = await webauthn_manager.verify_registration(
            credential=valid_registration_credential,
            challenge="test-challenge",
            user_id="test-user"
        )

        assert result.verified is False
        assert "Test error" in result.error


class TestWebAuthnAuthentication:
    """Test WebAuthn authentication functionality."""

    @pytest.fixture
    def webauthn_manager(self):
        """Create WebAuthn manager with mocked settings."""
        with patch('src.infrastructure.auth.webauthn_manager.settings') as mock_settings:
            mock_settings.WEBAUTHN_RP_ID = "example.com"
            mock_settings.WEBAUTHN_USER_VERIFICATION = "required"
            mock_settings.CORS_ORIGINS = ["https://example.com"]
            mock_settings.APP_ENV = "test"
            return WebAuthnManager()

    @pytest.fixture
    def valid_auth_credential(self):
        """Valid authentication credential."""
        return DeviceAuthenticationVerification(
            id="test-credential-id",
            raw_id="test-raw-id",
            response=DeviceAuthenticationResponse(
                client_data_json="eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
                authenticator_data="base64-encoded-auth-data",
                signature="base64-encoded-signature"
            ),
            type="public-key"
        )

    @pytest.fixture
    def mock_validators(self):
        """Mock all validators."""
        with patch('src.infrastructure.auth.webauthn_manager.WebAuthnValidator') as webauthn_mock, \
             patch('src.infrastructure.auth.webauthn_manager.CredentialValidator') as cred_mock:
            yield webauthn_mock, cred_mock

    async def test_verify_authentication_success(
        self, webauthn_manager, mock_validators, valid_auth_credential
    ):
        """Test successful authentication verification."""
        webauthn_mock, cred_mock = mock_validators

        # Setup valid client data
        webauthn_mock.validate_client_data_json.return_value = {
            "type": "webauthn.get",
            "challenge": "test-challenge",
            "origin": "https://example.com"
        }
        webauthn_mock.validate_challenge.return_value = True
        webauthn_mock.validate_origin.return_value = True
        webauthn_mock.validate_counter.return_value = True
        webauthn_mock.validate_base64.return_value = b"mock_data"

        # Setup authenticator data (37 bytes minimum)
        auth_data = bytearray(37)
        auth_data[32] = 0x05  # Flags: UP=1, UV=1
        auth_data[33:37] = (10).to_bytes(4, 'big')  # Counter = 10
        
        with patch('base64.urlsafe_b64decode', return_value=auth_data):
            cred_mock.decode_public_key.return_value = {"1": 2, "3": -7}
            cred_mock.verify_signature.return_value = True

            result = await webauthn_manager.verify_authentication(
                credential=valid_auth_credential,
                challenge="test-challenge",
                public_key="mock-public-key",
                sign_count=5
            )

            assert result.verified is True
            assert result.new_sign_count == 10
            assert result.error is None

    async def test_verify_authentication_invalid_client_data_type(
        self, webauthn_manager, mock_validators, valid_auth_credential
    ):
        """Test authentication verification with invalid client data type."""
        webauthn_mock, _ = mock_validators

        webauthn_mock.validate_client_data_json.return_value = {
            "type": "webauthn.create",  # Wrong type
            "challenge": "test-challenge",
            "origin": "https://example.com"
        }

        result = await webauthn_manager.verify_authentication(
            credential=valid_auth_credential,
            challenge="test-challenge",
            public_key="mock-public-key",
            sign_count=5
        )

        assert result.verified is False
        assert result.error == "Invalid client data type"

    async def test_verify_authentication_challenge_mismatch(
        self, webauthn_manager, mock_validators, valid_auth_credential
    ):
        """Test authentication verification with challenge mismatch."""
        webauthn_mock, _ = mock_validators

        webauthn_mock.validate_client_data_json.return_value = {
            "type": "webauthn.get",
            "challenge": "test-challenge",
            "origin": "https://example.com"
        }
        webauthn_mock.validate_challenge.return_value = False

        result = await webauthn_manager.verify_authentication(
            credential=valid_auth_credential,
            challenge="different-challenge",
            public_key="mock-public-key",
            sign_count=5
        )

        assert result.verified is False
        assert result.error == "Challenge mismatch"

    async def test_verify_authentication_user_presence_not_detected(
        self, webauthn_manager, mock_validators, valid_auth_credential
    ):
        """Test authentication verification without user presence."""
        webauthn_mock, _ = mock_validators

        webauthn_mock.validate_client_data_json.return_value = {
            "type": "webauthn.get",
            "challenge": "test-challenge",
            "origin": "https://example.com"
        }
        webauthn_mock.validate_challenge.return_value = True
        webauthn_mock.validate_origin.return_value = True

        # Setup authenticator data without user presence flag
        auth_data = bytearray(37)
        auth_data[32] = 0x00  # Flags: UP=0, UV=0
        
        with patch('base64.urlsafe_b64decode', return_value=auth_data):
            result = await webauthn_manager.verify_authentication(
                credential=valid_auth_credential,
                challenge="test-challenge",
                public_key="mock-public-key",
                sign_count=5
            )

            assert result.verified is False
            assert result.error == "User presence not detected"

    async def test_verify_authentication_user_verification_required(
        self, webauthn_manager, mock_validators, valid_auth_credential
    ):
        """Test authentication verification when user verification is required but not performed."""
        webauthn_mock, _ = mock_validators

        webauthn_mock.validate_client_data_json.return_value = {
            "type": "webauthn.get",
            "challenge": "test-challenge",
            "origin": "https://example.com"
        }
        webauthn_mock.validate_challenge.return_value = True
        webauthn_mock.validate_origin.return_value = True

        # Setup authenticator data with UP but not UV
        auth_data = bytearray(37)
        auth_data[32] = 0x01  # Flags: UP=1, UV=0
        
        with patch('base64.urlsafe_b64decode', return_value=auth_data):
            result = await webauthn_manager.verify_authentication(
                credential=valid_auth_credential,
                challenge="test-challenge",
                public_key="mock-public-key",
                sign_count=5
            )

            assert result.verified is False
            assert result.error == "User verification required but not performed"

    async def test_verify_authentication_invalid_counter(
        self, webauthn_manager, mock_validators, valid_auth_credential
    ):
        """Test authentication verification with invalid counter."""
        webauthn_mock, _ = mock_validators

        webauthn_mock.validate_client_data_json.return_value = {
            "type": "webauthn.get",
            "challenge": "test-challenge",
            "origin": "https://example.com"
        }
        webauthn_mock.validate_challenge.return_value = True
        webauthn_mock.validate_origin.return_value = True
        webauthn_mock.validate_counter.return_value = False

        # Setup valid authenticator data
        auth_data = bytearray(37)
        auth_data[32] = 0x05  # Flags: UP=1, UV=1
        auth_data[33:37] = (3).to_bytes(4, 'big')  # Counter = 3
        
        with patch('base64.urlsafe_b64decode', return_value=auth_data):
            result = await webauthn_manager.verify_authentication(
                credential=valid_auth_credential,
                challenge="test-challenge",
                public_key="mock-public-key",
                sign_count=5  # Higher than new counter
            )

            assert result.verified is False
            assert result.error == "Invalid counter - possible replay attack"

    async def test_verify_authentication_signature_verification_failed(
        self, webauthn_manager, mock_validators, valid_auth_credential
    ):
        """Test authentication verification with failed signature verification."""
        webauthn_mock, cred_mock = mock_validators

        webauthn_mock.validate_client_data_json.return_value = {
            "type": "webauthn.get",
            "challenge": "test-challenge",
            "origin": "https://example.com"
        }
        webauthn_mock.validate_challenge.return_value = True
        webauthn_mock.validate_origin.return_value = True
        webauthn_mock.validate_counter.return_value = True
        webauthn_mock.validate_base64.return_value = b"mock_data"

        # Setup valid authenticator data
        auth_data = bytearray(37)
        auth_data[32] = 0x05  # Flags: UP=1, UV=1
        auth_data[33:37] = (10).to_bytes(4, 'big')  # Counter = 10
        
        with patch('base64.urlsafe_b64decode', return_value=auth_data):
            cred_mock.decode_public_key.return_value = {"1": 2, "3": -7}
            cred_mock.verify_signature.return_value = False  # Signature verification fails

            result = await webauthn_manager.verify_authentication(
                credential=valid_auth_credential,
                challenge="test-challenge",
                public_key="mock-public-key",
                sign_count=5
            )

            assert result.verified is False
            assert result.error == "Signature verification failed"

    async def test_verify_authentication_invalid_authenticator_data(
        self, webauthn_manager, mock_validators, valid_auth_credential
    ):
        """Test authentication verification with invalid authenticator data."""
        webauthn_mock, _ = mock_validators

        webauthn_mock.validate_client_data_json.return_value = {
            "type": "webauthn.get",
            "challenge": "test-challenge",
            "origin": "https://example.com"
        }
        webauthn_mock.validate_challenge.return_value = True
        webauthn_mock.validate_origin.return_value = True

        # Setup invalid authenticator data (too short)
        auth_data = bytearray(30)  # Less than 37 bytes
        
        with patch('base64.urlsafe_b64decode', return_value=auth_data):
            result = await webauthn_manager.verify_authentication(
                credential=valid_auth_credential,
                challenge="test-challenge",
                public_key="mock-public-key",
                sign_count=5
            )

            assert result.verified is False
            assert result.error == "Invalid authenticator data"

    async def test_verify_authentication_exception_handling(
        self, webauthn_manager, mock_validators, valid_auth_credential
    ):
        """Test authentication verification exception handling."""
        webauthn_mock, _ = mock_validators

        # Setup mock to raise exception
        webauthn_mock.validate_client_data_json.side_effect = Exception("Test error")

        result = await webauthn_manager.verify_authentication(
            credential=valid_auth_credential,
            challenge="test-challenge",
            public_key="mock-public-key",
            sign_count=5
        )

        assert result.verified is False
        assert "Test error" in result.error


class TestVerificationResult:
    """Test VerificationResult class."""

    def test_verification_result_initialization(self):
        """Test VerificationResult initialization."""
        result = VerificationResult(
            verified=True,
            public_key="test-key",
            sign_count=5,
            attestation_type="direct"
        )

        assert result.verified is True
        assert result.public_key == "test-key"
        assert result.sign_count == 5
        assert result.attestation_type == "direct"
        assert result.error is None
        assert result.new_sign_count is None
        assert result.attestation_data is None
        assert result.aaguid is None

    def test_verification_result_with_error(self):
        """Test VerificationResult with error."""
        result = VerificationResult(
            verified=False,
            error="Test error"
        )

        assert result.verified is False
        assert result.error == "Test error"
        assert result.public_key is None

    def test_verification_result_with_aaguid(self):
        """Test VerificationResult with AAGUID."""
        test_uuid = uuid4()
        result = VerificationResult(
            verified=True,
            aaguid=test_uuid
        )

        assert result.verified is True
        assert result.aaguid == test_uuid

    def test_verification_result_with_attestation_data(self):
        """Test VerificationResult with attestation data."""
        attestation_data = {
            "fmt": "packed",
            "aaguid": "12345678-1234-5678-9012-123456789012",
            "flags": {"up": True, "uv": True}
        }
        
        result = VerificationResult(
            verified=True,
            attestation_data=attestation_data
        )

        assert result.verified is True
        assert result.attestation_data == attestation_data