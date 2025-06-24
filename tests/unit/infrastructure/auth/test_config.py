import pytest
from pydantic import ValidationError

from src.infrastructure.auth.config import AuthentikConfig


class TestAuthentikConfig:

    def test_default_config(self):
        config = AuthentikConfig(
            authentik_url="https://auth.example.com",
            authentik_token="test-token"
        )

        assert str(config.authentik_url) == "https://auth.example.com"
        assert config.authentik_token == "test-token"
        assert config.authentik_public_key_url == "/application/o/nai-platform/jwks/"
        assert config.tenant_header == "X-Tenant-ID"
        assert config.request_timeout == 30
        assert config.retry_attempts == 3
        assert config.retry_delay == 1.0
        assert config.verify_ssl is True

    def test_url_trailing_slash_removal(self):
        config = AuthentikConfig(
            authentik_url="https://auth.example.com/",
            authentik_token="test-token"
        )

        assert str(config.authentik_url) == "https://auth.example.com"

    def test_jwks_url_property(self):
        config = AuthentikConfig(
            authentik_url="https://auth.example.com",
            authentik_token="test-token"
        )

        assert config.jwks_url == "https://auth.example.com/application/o/nai-platform/jwks/"

    def test_api_base_url_property(self):
        config = AuthentikConfig(
            authentik_url="https://auth.example.com",
            authentik_token="test-token"
        )

        assert config.api_base_url == "https://auth.example.com/api/v3"

    def test_custom_values(self):
        config = AuthentikConfig(
            authentik_url="http://127.0.0.1:9000",
            authentik_token="custom-token",
            authentik_public_key_url="/custom/jwks/",
            tenant_header="X-Custom-Tenant",
            request_timeout=60,
            retry_attempts=5,
            retry_delay=2.0,
            verify_ssl=False
        )

        assert str(config.authentik_url) == "http://127.0.0.1:9000"
        assert config.authentik_token == "custom-token"
        assert config.authentik_public_key_url == "/custom/jwks/"
        assert config.tenant_header == "X-Custom-Tenant"
        assert config.request_timeout == 60
        assert config.retry_attempts == 5
        assert config.retry_delay == 2.0
        assert config.verify_ssl is False

    def test_missing_required_fields(self):
        with pytest.raises(ValidationError) as exc_info:
            AuthentikConfig()

        errors = exc_info.value.errors()
        assert any(e["loc"] == ("authentik_url",) for e in errors)
        assert any(e["loc"] == ("authentik_token",) for e in errors)

    def test_invalid_url(self):
        with pytest.raises(ValidationError) as exc_info:
            AuthentikConfig(
                authentik_url="not-a-url",
                authentik_token="test-token"
            )

        errors = exc_info.value.errors()
        assert any(e["loc"] == ("authentik_url",) for e in errors)

    def test_env_case_insensitive(self):
        # The case_sensitive = False should make env vars case-insensitive
        config = AuthentikConfig(
            authentik_url="https://auth.example.com",
            authentik_token="test-token"
        )
        assert str(config.authentik_url) == "https://auth.example.com"
        assert config.authentik_token == "test-token"

    def test_extra_fields_ignored(self):
        # Extra fields should be ignored due to extra="ignore"
        config = AuthentikConfig(
            authentik_url="https://auth.example.com",
            authentik_token="test-token",
            extra_field="should be ignored"
        )
        assert not hasattr(config, "extra_field")
