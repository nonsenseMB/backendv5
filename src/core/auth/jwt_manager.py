"""JWT token management for internal API authentication."""
from datetime import UTC, datetime, timedelta
from typing import Any

from jose import JWTError, jwt
from pydantic import BaseModel, Field

from src.core.config import settings
from src.core.logging import get_logger

logger = get_logger(__name__)


class TokenPayload(BaseModel):
    """JWT token payload structure."""

    sub: str  # User ID
    tenant_id: str
    session_id: str
    scopes: list[str] = Field(default_factory=list)
    iat: int
    exp: int
    iss: str
    aud: str
    jti: str | None = None  # JWT ID for tracking


class JWTManager:
    """Manages JWT token creation and validation for internal API use."""

    def __init__(self):
        # Use configured algorithm (RS256 or HS256)
        self.algorithm = settings.JWT_ALGORITHM
        self.issuer = settings.JWT_ISSUER
        self.audience = settings.JWT_AUDIENCE
        self.access_token_expire_minutes = settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
        self.refresh_token_expire_days = settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS

        # Generate or load private key for signing
        self._load_signing_keys()

    def _load_signing_keys(self):
        """Load keys for JWT signing."""
        if self.algorithm.startswith("RS"):
            # RSA algorithms need RSA key pairs
            if not settings.JWT_PRIVATE_KEY_PATH or not settings.JWT_PUBLIC_KEY_PATH:
                raise ValueError(
                    "JWT_PRIVATE_KEY_PATH and JWT_PUBLIC_KEY_PATH must be set for RSA algorithms"
                )
            
            # Load private key for signing
            from pathlib import Path
            private_key_path = Path(settings.JWT_PRIVATE_KEY_PATH)
            if not private_key_path.exists():
                raise FileNotFoundError(f"Private key not found: {private_key_path}")
            
            with open(private_key_path, "rb") as f:
                self.private_key = f.read()
            
            # Load public key for verification (optional, but good to validate)
            public_key_path = Path(settings.JWT_PUBLIC_KEY_PATH)
            if not public_key_path.exists():
                raise FileNotFoundError(f"Public key not found: {public_key_path}")
            
            with open(public_key_path, "rb") as f:
                self.public_key = f.read()
            
            # For RSA, we use private key for encoding
            self.secret_key = self.private_key
            
            logger.info("RSA keys loaded", 
                       algorithm=self.algorithm,
                       private_key_path=str(private_key_path),
                       public_key_path=str(public_key_path))
        else:
            # Symmetric algorithms use secret key
            self.secret_key = settings.SECRET_KEY
            logger.info("Symmetric key loaded", algorithm=self.algorithm)

        logger.info("JWT signing keys loaded", algorithm=self.algorithm)

    def create_access_token(
        self,
        user_id: str,
        tenant_id: str,
        session_id: str,
        scopes: list[str] | None = None,
        additional_claims: dict[str, Any] | None = None,
    ) -> str:
        """Create a new access token."""
        now = datetime.now(UTC)
        expires_at = now + timedelta(minutes=self.access_token_expire_minutes)

        payload = {
            "sub": user_id,
            "tenant_id": tenant_id,
            "session_id": session_id,
            "scopes": scopes or [],
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "iss": self.issuer,
            "aud": self.audience,
            "type": "access",
        }

        if additional_claims:
            payload.update(additional_claims)

        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

        logger.info(
            "Access token created",
            user_id=user_id,
            tenant_id=tenant_id,
            session_id=session_id,
            expires_in_minutes=self.access_token_expire_minutes,
        )

        return token

    def create_refresh_token(
        self,
        user_id: str,
        tenant_id: str,
        session_id: str,
    ) -> str:
        """Create a new refresh token."""
        now = datetime.now(UTC)
        expires_at = now + timedelta(days=self.refresh_token_expire_days)

        payload = {
            "sub": user_id,
            "tenant_id": tenant_id,
            "session_id": session_id,
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "iss": self.issuer,
            "aud": self.audience,
            "type": "refresh",
        }

        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

        logger.info(
            "Refresh token created",
            user_id=user_id,
            tenant_id=tenant_id,
            session_id=session_id,
            expires_in_days=self.refresh_token_expire_days,
        )

        return token

    def decode_token(self, token: str, token_type: str = "access") -> TokenPayload:
        """Decode and validate a JWT token."""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                audience=self.audience,
                issuer=self.issuer,
            )

            # Verify token type
            if payload.get("type") != token_type:
                raise JWTError(f"Invalid token type. Expected {token_type}")

            # Convert to TokenPayload
            token_payload = TokenPayload(
                sub=payload["sub"],
                tenant_id=payload["tenant_id"],
                session_id=payload["session_id"],
                scopes=payload.get("scopes", []),
                iat=payload["iat"],
                exp=payload["exp"],
                iss=payload["iss"],
                aud=payload["aud"],
                jti=payload.get("jti"),
            )

            logger.debug(
                "Token decoded successfully",
                user_id=token_payload.sub,
                tenant_id=token_payload.tenant_id,
                token_type=token_type,
            )

            return token_payload

        except JWTError as e:
            logger.warning(
                "JWT validation failed",
                error=str(e),
                token_type=token_type,
            )
            raise

    def decode_access_token(self, token: str) -> TokenPayload:
        """Decode and validate an access token."""
        return self.decode_token(token, token_type="access")

    def decode_refresh_token(self, token: str) -> TokenPayload:
        """Decode and validate a refresh token."""
        return self.decode_token(token, token_type="refresh")

    def refresh_access_token(self, refresh_token: str) -> tuple[str, str]:
        """Create new access and refresh tokens from a valid refresh token."""
        # Decode the refresh token
        payload = self.decode_refresh_token(refresh_token)

        # Create new tokens
        new_access_token = self.create_access_token(
            user_id=payload.sub,
            tenant_id=payload.tenant_id,
            session_id=payload.session_id,
            scopes=payload.scopes,
        )

        new_refresh_token = self.create_refresh_token(
            user_id=payload.sub,
            tenant_id=payload.tenant_id,
            session_id=payload.session_id,
        )

        logger.info(
            "Tokens refreshed",
            user_id=payload.sub,
            tenant_id=payload.tenant_id,
            session_id=payload.session_id,
        )

        return new_access_token, new_refresh_token
