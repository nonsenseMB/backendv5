
from pydantic import ConfigDict, Field, HttpUrl, field_validator, model_validator
from pydantic_settings import BaseSettings


class AuthentikConfig(BaseSettings):
    model_config = ConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore"
    )

    authentik_url: str = Field(
        default=None,
        validation_alias="AUTHENTIK_PUBLIC_URL",
        description="Base URL of the Authentik server"
    )
    authentik_token: str = Field(
        default=None,
        validation_alias="AUTHENTIK_BOOTSTRAP_TOKEN",
        description="Admin API token for Authentik"
    )
    authentik_public_key_url: str = Field(
        default="/application/o/nai-backend-dev/jwks/",
        description="Path to JWKS endpoint"
    )

    tenant_header: str = Field(
        default="X-Tenant-ID",
        description="Header name for tenant identification"
    )

    request_timeout: int = Field(
        default=30,
        description="Request timeout in seconds"
    )

    retry_attempts: int = Field(
        default=3,
        description="Number of retry attempts for failed requests"
    )

    retry_delay: float = Field(
        default=1.0,
        description="Delay between retry attempts in seconds"
    )

    verify_ssl: bool = Field(
        default=True,
        description="Verify SSL certificates"
    )

    # JWT Configuration
    jwt_algorithm: str = Field(
        default="RS256",
        description="JWT signing algorithm"
    )
    jwt_issuer: str | None = Field(
        default=None,
        description="Expected JWT issuer"
    )
    jwt_audience: str = Field(
        default="nai-backend-dev",
        description="Expected JWT audience"
    )
    jwt_leeway_seconds: int = Field(
        default=10,
        description="Leeway in seconds for time-based claims"
    )

    @model_validator(mode="after")
    def validate_required_fields(self):
        if not self.authentik_url:
            raise ValueError("AUTHENTIK_PUBLIC_URL environment variable is required")
        if not self.authentik_token:
            raise ValueError("AUTHENTIK_BOOTSTRAP_TOKEN environment variable is required")

        # Set JWT issuer based on Authentik URL if not explicitly set
        if not self.jwt_issuer:
            self.jwt_issuer = f"{self.authentik_url}/application/o/{self.jwt_audience}/"

        return self

    @field_validator("authentik_url", mode="after")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if v and v.endswith("/"):
            v = v[:-1]
        # Validate it's a valid URL
        if v:
            HttpUrl(v)
        return v

    @property
    def jwks_url(self) -> str:
        return f"{self.authentik_url}{self.authentik_public_key_url}"

    @property
    def api_base_url(self) -> str:
        return f"{self.authentik_url}/api/v3"
