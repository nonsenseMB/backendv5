"""Tests for security checks"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
import httpx
from src.core.auth.security_checks import SecurityChecker, SecurityCheckError


class TestSecurityChecker:
    """Test security checks functionality"""

    @pytest.fixture
    def security_checker(self):
        """Create a SecurityChecker instance"""
        return SecurityChecker()

    @pytest.fixture
    def mock_settings(self):
        """Mock settings for testing"""
        with patch("src.core.auth.security_checks.settings") as mock:
            mock.PASSWORD_AUTH_ENABLED = False
            mock.DEVICE_AUTH_REQUIRED = True
            mock.AUTHENTIK_URL = "http://127.0.0.1:9000"
            mock.AUTHENTIK_TIMEOUT_SECONDS = 30
            mock.AUTHENTIK_VERIFY_SSL = True
            mock.JWT_ALGORITHM = "RS256"
            mock.JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 15
            mock.JWT_REFRESH_TOKEN_EXPIRE_DAYS = 30
            mock.WEBAUTHN_USER_VERIFICATION = "required"
            mock.WEBAUTHN_RP_ID = "example.com"
            mock.APP_ENV = "development"
            mock.SESSION_TIMEOUT_MINUTES = 480
            mock.ENFORCE_MFA = True
            mock.CORS_ORIGINS = ["http://localhost:3000"]
            mock.REDIS_URL = "redis://localhost:6379"
            yield mock

    def test_check_password_auth_disabled_success(self, security_checker, mock_settings):
        """Test password auth check when disabled (success)"""
        mock_settings.PASSWORD_AUTH_ENABLED = False
        result = security_checker._check_password_auth_disabled()
        assert result is True

    def test_check_password_auth_disabled_failure(self, security_checker, mock_settings):
        """Test password auth check when enabled (failure)"""
        mock_settings.PASSWORD_AUTH_ENABLED = True
        with pytest.raises(SecurityCheckError, match="Password authentication must be disabled"):
            security_checker._check_password_auth_disabled()

    def test_check_device_auth_required_success(self, security_checker, mock_settings):
        """Test device auth check when required (success)"""
        mock_settings.DEVICE_AUTH_REQUIRED = True
        result = security_checker._check_device_auth_required()
        assert result is True

    def test_check_device_auth_required_failure(self, security_checker, mock_settings):
        """Test device auth check when not required (failure)"""
        mock_settings.DEVICE_AUTH_REQUIRED = False
        with pytest.raises(SecurityCheckError, match="Device authentication must be required"):
            security_checker._check_device_auth_required()

    @pytest.mark.asyncio
    async def test_check_authentik_connectivity_success(self, security_checker, mock_settings):
        """Test Authentik connectivity check success"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"issuer": "http://127.0.0.1:9000"}

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = await security_checker._check_authentik_connectivity()
            assert result is True

            # Verify the correct URL was called
            mock_client.get.assert_called_once_with(
                "http://127.0.0.1:9000/.well-known/openid-configuration"
            )

    @pytest.mark.asyncio
    async def test_check_authentik_connectivity_connect_error(self, security_checker, mock_settings):
        """Test Authentik connectivity check with connection error"""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.get.side_effect = httpx.ConnectError("Connection failed")
            mock_client_class.return_value = mock_client

            with pytest.raises(SecurityCheckError, match="Cannot connect to Authentik"):
                await security_checker._check_authentik_connectivity()

    @pytest.mark.asyncio
    async def test_check_authentik_connectivity_timeout(self, security_checker, mock_settings):
        """Test Authentik connectivity check with timeout"""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.get.side_effect = httpx.TimeoutException("Timeout")
            mock_client_class.return_value = mock_client

            with pytest.raises(SecurityCheckError, match="Timeout connecting to Authentik"):
                await security_checker._check_authentik_connectivity()

    @pytest.mark.asyncio
    async def test_check_authentik_connectivity_invalid_response(self, security_checker, mock_settings):
        """Test Authentik connectivity check with invalid response"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}  # Missing issuer field

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            with pytest.raises(SecurityCheckError, match="Invalid OpenID configuration"):
                await security_checker._check_authentik_connectivity()

    def test_check_jwt_configuration(self, security_checker, mock_settings):
        """Test JWT configuration check"""
        result = security_checker._check_jwt_configuration()
        assert result is True

    def test_check_webauthn_configuration_success(self, security_checker, mock_settings):
        """Test WebAuthn configuration check success"""
        mock_settings.WEBAUTHN_RP_ID = "example.com"
        mock_settings.APP_ENV = "development"
        result = security_checker._check_webauthn_configuration()
        assert result is True

    def test_check_webauthn_configuration_localhost_production(self, security_checker, mock_settings):
        """Test WebAuthn configuration check with localhost in production"""
        mock_settings.WEBAUTHN_RP_ID = "localhost"
        mock_settings.APP_ENV = "production"
        with pytest.raises(SecurityCheckError, match="WebAuthn RP ID cannot be 'localhost'"):
            security_checker._check_webauthn_configuration()

    def test_check_session_configuration(self, security_checker, mock_settings):
        """Test session configuration check"""
        result = security_checker._check_session_configuration()
        assert result is True

    def test_check_cors_configuration_success(self, security_checker, mock_settings):
        """Test CORS configuration check success"""
        mock_settings.CORS_ORIGINS = ["https://app.example.com"]
        mock_settings.APP_ENV = "production"
        result = security_checker._check_cors_configuration()
        assert result is True

    def test_check_cors_configuration_wildcard_production(self, security_checker, mock_settings):
        """Test CORS configuration check with wildcard in production"""
        mock_settings.CORS_ORIGINS = ["*"]
        mock_settings.APP_ENV = "production"
        with pytest.raises(SecurityCheckError, match="CORS origins cannot contain wildcards"):
            security_checker._check_cors_configuration()

    def test_check_ssl_configuration_success(self, security_checker, mock_settings):
        """Test SSL configuration check success"""
        mock_settings.AUTHENTIK_VERIFY_SSL = True
        mock_settings.APP_ENV = "production"
        result = security_checker._check_ssl_configuration()
        assert result is True

    def test_check_ssl_configuration_disabled_production(self, security_checker, mock_settings):
        """Test SSL configuration check with SSL disabled in production"""
        mock_settings.AUTHENTIK_VERIFY_SSL = False
        mock_settings.APP_ENV = "production"
        with pytest.raises(SecurityCheckError, match="SSL verification for Authentik must be enabled"):
            security_checker._check_ssl_configuration()

    @pytest.mark.asyncio
    async def test_run_all_checks_success(self, security_checker, mock_settings):
        """Test running all checks successfully"""
        # Mock the async Authentik connectivity check
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"issuer": "http://127.0.0.1:9000"}

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            with patch("src.core.auth.security_checks.log_audit_event") as mock_audit:
                result = await security_checker.run_all_checks()
                assert result is True
                assert len(security_checker.checks_passed) == 8
                assert len(security_checker.checks_failed) == 0

                # Verify audit event was logged
                mock_audit.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_all_checks_with_failures(self, security_checker):
        """Test running all checks with some failures"""
        # Create a new mock for this test to avoid state contamination
        with patch("src.core.auth.security_checks.settings") as mock_settings_local:
            # Configure all settings
            mock_settings_local.PASSWORD_AUTH_ENABLED = True  # This will fail
            mock_settings_local.DEVICE_AUTH_REQUIRED = True
            mock_settings_local.AUTHENTIK_URL = "http://127.0.0.1:9000"
            mock_settings_local.AUTHENTIK_TIMEOUT_SECONDS = 30
            mock_settings_local.AUTHENTIK_VERIFY_SSL = True
            mock_settings_local.JWT_ALGORITHM = "RS256"
            mock_settings_local.JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 15
            mock_settings_local.JWT_REFRESH_TOKEN_EXPIRE_DAYS = 30
            mock_settings_local.WEBAUTHN_USER_VERIFICATION = "required"
            mock_settings_local.WEBAUTHN_RP_ID = "example.com"
            mock_settings_local.APP_ENV = "development"
            mock_settings_local.SESSION_TIMEOUT_MINUTES = 480
            mock_settings_local.ENFORCE_MFA = True
            mock_settings_local.CORS_ORIGINS = ["http://localhost:3000"]
            mock_settings_local.REDIS_URL = "redis://localhost:6379"

            # Mock the async Authentik connectivity check
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"issuer": "http://127.0.0.1:9000"}

            with patch("httpx.AsyncClient") as mock_client_class:
                mock_client = AsyncMock()
                mock_client.__aenter__.return_value = mock_client
                mock_client.get.return_value = mock_response
                mock_client_class.return_value = mock_client

                with patch("src.core.auth.security_checks.log_audit_event") as mock_audit:
                    result = await security_checker.run_all_checks()
                    assert result is False
                    assert len(security_checker.checks_failed) > 0
                    assert any("Password Authentication" in check[0] for check in security_checker.checks_failed)

    def test_get_summary(self, security_checker):
        """Test getting security check summary"""
        security_checker.checks_passed = ["Check 1", "Check 2"]
        security_checker.checks_failed = [("Check 3", "Error message")]

        summary = security_checker.get_summary()
        assert "Security Check Summary" in summary
        assert "✓ Check 1" in summary
        assert "✓ Check 2" in summary
        assert "✗ Check 3: Error message" in summary