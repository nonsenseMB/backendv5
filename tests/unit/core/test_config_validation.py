"""Tests for configuration validation"""

import pytest
from pydantic import ValidationError
from src.core.config import Settings


class TestConfigValidation:
    """Test configuration validation rules"""

    def test_valid_configuration(self):
        """Test that valid configuration passes validation"""
        settings = Settings(
            AUTHENTIK_URL="https://auth.example.com",
            PASSWORD_AUTH_ENABLED=False,
            DEVICE_AUTH_REQUIRED=True,
            WEBAUTHN_RP_ID="example.com",
            WEBAUTHN_RP_NAME="Example App",
            WEBAUTHN_USER_VERIFICATION="required",
            WEBAUTHN_ATTESTATION="direct",
            SESSION_TIMEOUT_MINUTES=480,
            MAX_FAILED_LOGIN_ATTEMPTS=5,
            LOCKOUT_DURATION_MINUTES=15,
        )
        assert settings.AUTHENTIK_URL == "https://auth.example.com"
        assert not settings.PASSWORD_AUTH_ENABLED
        assert settings.DEVICE_AUTH_REQUIRED

    def test_authentik_url_trailing_slash_removed(self):
        """Test that trailing slash is removed from AUTHENTIK_URL"""
        settings = Settings(
            AUTHENTIK_URL="https://auth.example.com/",
            PASSWORD_AUTH_ENABLED=False,
            DEVICE_AUTH_REQUIRED=True,
            WEBAUTHN_RP_ID="example.com",
            WEBAUTHN_RP_NAME="Example App",
        )
        assert settings.AUTHENTIK_URL == "https://auth.example.com"

    def test_jwt_issuer_trailing_slash_added(self):
        """Test that trailing slash is added to JWT_ISSUER"""
        settings = Settings(
            JWT_ISSUER="https://auth.example.com/app",
            PASSWORD_AUTH_ENABLED=False,
            DEVICE_AUTH_REQUIRED=True,
            WEBAUTHN_RP_ID="example.com",
            WEBAUTHN_RP_NAME="Example App",
        )
        assert settings.JWT_ISSUER == "https://auth.example.com/app/"

    def test_password_auth_disabled_requires_device_auth(self):
        """Test that device auth is required when password auth is disabled"""
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                PASSWORD_AUTH_ENABLED=False,
                DEVICE_AUTH_REQUIRED=False,
            )
        errors = exc_info.value.errors()
        assert any(
            "When PASSWORD_AUTH_ENABLED is false, DEVICE_AUTH_REQUIRED must be true"
            in str(error)
            for error in errors
        )

    def test_device_auth_requires_webauthn_config(self):
        """Test that WebAuthn config is required when device auth is enabled"""
        # Missing WEBAUTHN_RP_ID
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                PASSWORD_AUTH_ENABLED=False,
                DEVICE_AUTH_REQUIRED=True,
                WEBAUTHN_RP_ID="",
                WEBAUTHN_RP_NAME="Example App",
            )
        errors = exc_info.value.errors()
        assert any(
            "WEBAUTHN_RP_ID must be set when DEVICE_AUTH_REQUIRED is true" in str(error)
            for error in errors
        )

        # Missing WEBAUTHN_RP_NAME
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                PASSWORD_AUTH_ENABLED=False,
                DEVICE_AUTH_REQUIRED=True,
                WEBAUTHN_RP_ID="example.com",
                WEBAUTHN_RP_NAME="",
            )
        errors = exc_info.value.errors()
        assert any(
            "WEBAUTHN_RP_NAME must be set when DEVICE_AUTH_REQUIRED is true" in str(error)
            for error in errors
        )

    def test_invalid_webauthn_user_verification(self):
        """Test that invalid WebAuthn user verification values are rejected"""
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                WEBAUTHN_USER_VERIFICATION="invalid",
                PASSWORD_AUTH_ENABLED=False,
                DEVICE_AUTH_REQUIRED=True,
                WEBAUTHN_RP_ID="example.com",
                WEBAUTHN_RP_NAME="Example App",
            )
        errors = exc_info.value.errors()
        assert any("WEBAUTHN_USER_VERIFICATION must be one of" in str(error) for error in errors)

    def test_invalid_webauthn_attestation(self):
        """Test that invalid WebAuthn attestation values are rejected"""
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                WEBAUTHN_ATTESTATION="invalid",
                PASSWORD_AUTH_ENABLED=False,
                DEVICE_AUTH_REQUIRED=True,
                WEBAUTHN_RP_ID="example.com",
                WEBAUTHN_RP_NAME="Example App",
            )
        errors = exc_info.value.errors()
        assert any("WEBAUTHN_ATTESTATION must be one of" in str(error) for error in errors)

    def test_session_timeout_validation(self):
        """Test session timeout validation"""
        # Too low
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                SESSION_TIMEOUT_MINUTES=0,
                PASSWORD_AUTH_ENABLED=False,
                DEVICE_AUTH_REQUIRED=True,
                WEBAUTHN_RP_ID="example.com",
                WEBAUTHN_RP_NAME="Example App",
            )
        errors = exc_info.value.errors()
        assert any("SESSION_TIMEOUT_MINUTES must be between" in str(error) for error in errors)

        # Too high
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                SESSION_TIMEOUT_MINUTES=20000,
                PASSWORD_AUTH_ENABLED=False,
                DEVICE_AUTH_REQUIRED=True,
                WEBAUTHN_RP_ID="example.com",
                WEBAUTHN_RP_NAME="Example App",
            )
        errors = exc_info.value.errors()
        assert any("SESSION_TIMEOUT_MINUTES must be between" in str(error) for error in errors)

    def test_lockout_configuration_validation(self):
        """Test lockout configuration validation"""
        # Invalid max failed attempts
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                MAX_FAILED_LOGIN_ATTEMPTS=0,
                PASSWORD_AUTH_ENABLED=False,
                DEVICE_AUTH_REQUIRED=True,
                WEBAUTHN_RP_ID="example.com",
                WEBAUTHN_RP_NAME="Example App",
            )
        errors = exc_info.value.errors()
        assert any("MAX_FAILED_LOGIN_ATTEMPTS must be at least 1" in str(error) for error in errors)

        # Invalid lockout duration
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                LOCKOUT_DURATION_MINUTES=0,
                PASSWORD_AUTH_ENABLED=False,
                DEVICE_AUTH_REQUIRED=True,
                WEBAUTHN_RP_ID="example.com",
                WEBAUTHN_RP_NAME="Example App",
            )
        errors = exc_info.value.errors()
        assert any("LOCKOUT_DURATION_MINUTES must be at least 1" in str(error) for error in errors)

    def test_jwt_rs256_requires_public_key(self):
        """Test that RS256 requires either Authentik public key URL or JWT public key path"""
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                JWT_ALGORITHM="RS256",
                AUTHENTIK_PUBLIC_KEY_URL="",
                JWT_PUBLIC_KEY_PATH=None,
                PASSWORD_AUTH_ENABLED=False,
                DEVICE_AUTH_REQUIRED=True,
                WEBAUTHN_RP_ID="example.com",
                WEBAUTHN_RP_NAME="Example App",
            )
        errors = exc_info.value.errors()
        assert any(
            "Either AUTHENTIK_PUBLIC_KEY_URL or JWT_PUBLIC_KEY_PATH must be set for RS256"
            in str(error)
            for error in errors
        )

    def test_cors_origins_parsing(self):
        """Test CORS origins parsing from different formats"""
        # Comma-separated string
        settings = Settings(
            CORS_ORIGINS="http://localhost:3000,http://localhost:3001",
            PASSWORD_AUTH_ENABLED=False,
            DEVICE_AUTH_REQUIRED=True,
            WEBAUTHN_RP_ID="example.com",
            WEBAUTHN_RP_NAME="Example App",
        )
        assert settings.CORS_ORIGINS == ["http://localhost:3000", "http://localhost:3001"]

        # JSON array string
        settings = Settings(
            CORS_ORIGINS='["http://localhost:3000","http://localhost:3001"]',
            PASSWORD_AUTH_ENABLED=False,
            DEVICE_AUTH_REQUIRED=True,
            WEBAUTHN_RP_ID="example.com",
            WEBAUTHN_RP_NAME="Example App",
        )
        assert settings.CORS_ORIGINS == ["http://localhost:3000", "http://localhost:3001"]

        # Already a list
        settings = Settings(
            CORS_ORIGINS=["http://localhost:3000", "http://localhost:3001"],
            PASSWORD_AUTH_ENABLED=False,
            DEVICE_AUTH_REQUIRED=True,
            WEBAUTHN_RP_ID="example.com",
            WEBAUTHN_RP_NAME="Example App",
        )
        assert settings.CORS_ORIGINS == ["http://localhost:3000", "http://localhost:3001"]