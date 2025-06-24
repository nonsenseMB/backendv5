from typing import Self

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "Backend v5"
    APP_VERSION: str = "0.1.0"
    APP_DOMAIN: str = "localhost"
    DEBUG: bool = False
    APP_ENV: str = "production"

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    RELOAD: bool = False
    WORKERS: int = 4

    # Database
    DATABASE_URL: str = "postgresql://user:password@localhost/dbname"
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 10

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_POOL_SIZE: int = 10

    # Security
    SECRET_KEY: str = "your-secret-key-here"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # JWT Configuration
    JWT_ALGORITHM: str = "RS256"
    JWT_ISSUER: str = "http://127.0.0.1:9000/application/o/nai-platform/"
    JWT_AUDIENCE: str = "nai-platform"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    JWT_LEEWAY_SECONDS: int = 10
    JWT_PRIVATE_KEY_PATH: str | None = None
    JWT_PUBLIC_KEY_PATH: str | None = None

    # Authentik Configuration
    AUTHENTIK_URL: str = "http://127.0.0.1:9000"
    AUTHENTIK_TOKEN: str = ""
    AUTHENTIK_PUBLIC_KEY_URL: str = "/application/o/nai-platform/jwks/"
    AUTHENTIK_CLIENT_ID: str = "nai-platform"
    AUTHENTIK_CLIENT_SECRET: str = ""
    AUTHENTIK_TIMEOUT_SECONDS: int = 30
    AUTHENTIK_VERIFY_SSL: bool = True
    AUTHENTIK_JWKS_CACHE_TTL_SECONDS: int = 3600
    AUTHENTIK_MAX_RETRIES: int = 3

    # Security Flags
    DEVICE_AUTH_REQUIRED: bool = True
    PASSWORD_AUTH_ENABLED: bool = False
    WEBAUTHN_USER_VERIFICATION: str = "required"
    WEBAUTHN_RP_ID: str = "localhost"
    WEBAUTHN_RP_NAME: str = "nAI Platform"
    WEBAUTHN_CHALLENGE_TIMEOUT: int = 60000
    WEBAUTHN_ATTESTATION: str = "direct"
    REQUIRE_TRUSTED_DEVICE: bool = True
    ENFORCE_MFA: bool = True
    SESSION_TIMEOUT_MINUTES: int = 480
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: list[str] = ["*"]
    CORS_ALLOW_HEADERS: list[str] = ["*"]

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"

    # OpenTelemetry
    OTEL_ENABLED: bool = False
    OTEL_SERVICE_NAME: str = "backendv5"
    OTEL_ENDPOINT: str = "http://localhost:4317"

    # API Keys
    API_KEY_HEADER: str = "X-API-Key"

    # Tenant
    DEFAULT_TENANT_ID: str = "default"
    ENABLE_MULTI_TENANCY: bool = False

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: str | list[str]) -> list[str]:
        if isinstance(v, str):
            # Handle JSON array strings
            if v.startswith("[") and v.endswith("]"):
                import json

                try:
                    return json.loads(v)
                except json.JSONDecodeError:
                    # If JSON parsing fails, treat as comma-separated
                    pass
            # Handle comma-separated strings
            return [i.strip() for i in v.split(",")]
        # Already a list, return as-is
        return v  # type: ignore

    @field_validator("AUTHENTIK_URL")
    @classmethod
    def validate_authentik_url(cls, v: str) -> str:
        if not v:
            raise ValueError("AUTHENTIK_URL must be provided")
        # Ensure URL doesn't end with slash for consistency
        return v.rstrip("/")

    @field_validator("JWT_ISSUER")
    @classmethod
    def validate_jwt_issuer(cls, v: str) -> str:
        # Ensure issuer ends with slash as per OAuth2 spec
        if not v.endswith("/"):
            return f"{v}/"
        return v

    @field_validator("WEBAUTHN_USER_VERIFICATION")
    @classmethod
    def validate_webauthn_verification(cls, v: str) -> str:
        allowed = ["required", "preferred", "discouraged"]
        if v not in allowed:
            raise ValueError(f"WEBAUTHN_USER_VERIFICATION must be one of {allowed}")
        return v

    @field_validator("WEBAUTHN_ATTESTATION")
    @classmethod
    def validate_webauthn_attestation(cls, v: str) -> str:
        allowed = ["none", "indirect", "direct", "enterprise"]
        if v not in allowed:
            raise ValueError(f"WEBAUTHN_ATTESTATION must be one of {allowed}")
        return v

    @model_validator(mode="after")
    def validate_security_configuration(self) -> Self:
        """Validate security configuration consistency"""
        # If password auth is disabled, device auth must be required
        if not self.PASSWORD_AUTH_ENABLED and not self.DEVICE_AUTH_REQUIRED:
            raise ValueError(
                "When PASSWORD_AUTH_ENABLED is false, DEVICE_AUTH_REQUIRED must be true"
            )

        # If device auth is required, WebAuthn must be properly configured
        if self.DEVICE_AUTH_REQUIRED and not self.WEBAUTHN_RP_ID:
            raise ValueError("WEBAUTHN_RP_ID must be set when DEVICE_AUTH_REQUIRED is true")
        if self.DEVICE_AUTH_REQUIRED and not self.WEBAUTHN_RP_NAME:
            raise ValueError("WEBAUTHN_RP_NAME must be set when DEVICE_AUTH_REQUIRED is true")

        # JWT configuration validation
        if self.JWT_ALGORITHM == "RS256" and not self.AUTHENTIK_PUBLIC_KEY_URL and not self.JWT_PUBLIC_KEY_PATH:
            raise ValueError(
                "Either AUTHENTIK_PUBLIC_KEY_URL or JWT_PUBLIC_KEY_PATH must be set for RS256"
            )

        # Session timeout must be reasonable
        if self.SESSION_TIMEOUT_MINUTES < 1 or self.SESSION_TIMEOUT_MINUTES > 10080:  # 1 week max
            raise ValueError("SESSION_TIMEOUT_MINUTES must be between 1 and 10080 (1 week)")

        # Lockout configuration validation
        if self.MAX_FAILED_LOGIN_ATTEMPTS < 1:
            raise ValueError("MAX_FAILED_LOGIN_ATTEMPTS must be at least 1")
        if self.LOCKOUT_DURATION_MINUTES < 1:
            raise ValueError("LOCKOUT_DURATION_MINUTES must be at least 1")

        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",  # Ignore extra fields like LOG_*
    )


settings = Settings()
