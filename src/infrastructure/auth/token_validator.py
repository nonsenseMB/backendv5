"""
JWT Token validation for Authentik-issued tokens.
Validates signatures, claims, and expiration.
"""
import time
from datetime import datetime
from typing import Any

from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError

from src.core.logging import get_logger

from .config import AuthentikConfig
from .exceptions import (
    AuthentikTokenExpiredError,
    AuthentikValidationError,
)
from .jwks_cache import JWKSCache

logger = get_logger(__name__)


class TokenValidator:
    """Validates JWT tokens issued by Authentik."""

    def __init__(
        self,
        config: AuthentikConfig | None = None,
        jwks_cache: JWKSCache | None = None
    ):
        self.config = config or AuthentikConfig()
        self.jwks_cache = jwks_cache or JWKSCache(config)

        # Expected values for validation
        self.expected_issuer = self.config.jwt_issuer if hasattr(self.config, 'jwt_issuer') else None
        self.expected_audience = self.config.jwt_audience if hasattr(self.config, 'jwt_audience') else None
        self.algorithm = self.config.jwt_algorithm if hasattr(self.config, 'jwt_algorithm') else "RS256"

        # Leeway for time-based claims (in seconds)
        self.leeway = 10

    async def validate_token(
        self,
        token: str,
        verify_exp: bool = True,
        verify_aud: bool = True,
        verify_iss: bool = True,
        required_claims: list[str] | None = None
    ) -> dict[str, Any]:
        """
        Validate a JWT token issued by Authentik.

        Args:
            token: The JWT token string
            verify_exp: Whether to verify expiration
            verify_aud: Whether to verify audience
            verify_iss: Whether to verify issuer
            required_claims: List of claims that must be present

        Returns:
            The validated token claims

        Raises:
            AuthentikValidationError: If validation fails
        """
        try:
            # First decode without verification to get the header
            unverified_header = jwt.get_unverified_header(token)
            unverified_claims = jwt.get_unverified_claims(token)

            kid = unverified_header.get("kid")
            if not kid:
                raise AuthentikValidationError("Token missing 'kid' in header")

            logger.debug("Validating token", kid=kid, jti=unverified_claims.get("jti"))

            # Get the signing key
            signing_key = await self.jwks_cache.get_signing_key(kid)
            if not signing_key:
                # Try refreshing the cache once
                logger.info("Key not found, refreshing JWKS cache", kid=kid)
                await self.jwks_cache.refresh()
                signing_key = await self.jwks_cache.get_signing_key(kid)

                if not signing_key:
                    raise AuthentikValidationError(f"No signing key found for kid: {kid}")

            # Build options for validation
            options = {
                "verify_signature": True,
                "verify_exp": verify_exp,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": verify_aud and self.expected_audience is not None,
                "verify_iss": verify_iss and self.expected_issuer is not None,
                "require_exp": verify_exp,
                "require_iat": True,
                "require_nbf": False,
            }

            # Add required claims to options
            if required_claims:
                for claim in required_claims:
                    options[f"require_{claim}"] = True

            # Validate the token
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=[self.algorithm],
                options=options,
                audience=self.expected_audience if verify_aud else None,
                issuer=self.expected_issuer if verify_iss else None
            )

            # Additional validation
            self._validate_claims(claims, required_claims)

            logger.info(
                "Token validated successfully",
                sub=claims.get("sub"),
                jti=claims.get("jti"),
                exp=datetime.fromtimestamp(claims.get("exp", 0)).isoformat()
            )

            return claims

        except ExpiredSignatureError as e:
            logger.warning("Token expired", error=str(e))
            raise AuthentikTokenExpiredError("Token has expired") from e

        except JWTClaimsError as e:
            logger.warning("Token claims validation failed", error=str(e))
            raise AuthentikValidationError(f"Invalid token claims: {str(e)}") from e

        except JWTError as e:
            logger.warning("JWT validation failed", error=str(e))
            raise AuthentikValidationError(f"Invalid token: {str(e)}") from e

        except Exception as e:
            logger.error("Unexpected error during token validation", error=str(e))
            raise AuthentikValidationError(f"Token validation failed: {str(e)}") from e

    def _validate_claims(self, claims: dict[str, Any], required_claims: list[str] | None = None):
        """
        Perform additional claim validation.

        Args:
            claims: The token claims
            required_claims: List of required claim names
        """
        # Check required claims
        if required_claims:
            missing_claims = [claim for claim in required_claims if claim not in claims]
            if missing_claims:
                raise AuthentikValidationError(f"Missing required claims: {missing_claims}")

        # Validate standard claims
        now = time.time()

        # Check not before (nbf)
        if "nbf" in claims:
            nbf = claims["nbf"]
            if now < (nbf - self.leeway):
                raise AuthentikValidationError("Token not yet valid")

        # Validate Authentik-specific claims
        if "sub" not in claims:
            raise AuthentikValidationError("Token missing 'sub' claim")

        # Log unusual claims for debugging
        standard_claims = {
            "iss", "sub", "aud", "exp", "nbf", "iat", "jti",
            "name", "email", "email_verified", "preferred_username",
            "given_name", "family_name", "groups", "sid"
        }

        unusual_claims = set(claims.keys()) - standard_claims
        if unusual_claims:
            logger.debug("Token contains non-standard claims", claims=list(unusual_claims))

    async def get_token_info(self, token: str) -> dict[str, Any]:
        """
        Get basic information about a token without full validation.

        Args:
            token: The JWT token

        Returns:
            Dict with token information
        """
        try:
            header = jwt.get_unverified_header(token)
            claims = jwt.get_unverified_claims(token)

            # Calculate token age and time to expiry
            now = time.time()
            iat = claims.get("iat", 0)
            exp = claims.get("exp", 0)

            token_age = now - iat if iat else None
            time_to_expiry = exp - now if exp else None

            return {
                "header": header,
                "claims": claims,
                "token_age_seconds": token_age,
                "time_to_expiry_seconds": time_to_expiry,
                "is_expired": time_to_expiry < 0 if time_to_expiry is not None else None,
                "issuer": claims.get("iss"),
                "subject": claims.get("sub"),
                "audience": claims.get("aud"),
                "jti": claims.get("jti"),
                "kid": header.get("kid"),
                "algorithm": header.get("alg")
            }

        except Exception as e:
            logger.error("Failed to get token info", error=str(e))
            return {"error": str(e)}

    async def validate_access_token(self, token: str) -> dict[str, Any]:
        """
        Validate an access token with standard checks.

        Args:
            token: The access token

        Returns:
            The validated claims
        """
        return await self.validate_token(
            token,
            verify_exp=True,
            verify_aud=True,
            verify_iss=True,
            required_claims=["sub", "iat"]
        )

    async def validate_id_token(self, token: str) -> dict[str, Any]:
        """
        Validate an ID token with OpenID Connect standard checks.

        Args:
            token: The ID token

        Returns:
            The validated claims
        """
        claims = await self.validate_token(
            token,
            verify_exp=True,
            verify_aud=True,
            verify_iss=True,
            required_claims=["sub", "iat", "auth_time"]
        )

        # Additional OIDC validations
        if "nonce" in claims and not claims.get("nonce"):
            raise AuthentikValidationError("ID token has empty nonce")

        return claims

    async def close(self):
        """Close resources."""
        if hasattr(self.jwks_cache, 'close'):
            await self.jwks_cache.close()
