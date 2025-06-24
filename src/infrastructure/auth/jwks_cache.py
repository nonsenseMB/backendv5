"""
JWKS (JSON Web Key Set) caching for Authentik JWT validation.
Provides efficient caching of public keys with automatic refresh.
"""
import time
from datetime import datetime
from typing import Any

import httpx
from cachetools import TTLCache
from jose import jwk

from src.core.logging import get_logger

from .config import AuthentikConfig
from .exceptions import AuthentikError

logger = get_logger(__name__)


class JWKSCache:
    """Cache for JSON Web Key Set from Authentik."""

    def __init__(self, config: AuthentikConfig | None = None):
        self.config = config or AuthentikConfig()
        # TTL cache with 1 hour expiry
        self._cache: TTLCache = TTLCache(maxsize=10, ttl=3600)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            verify=self.config.verify_ssl
        )
        self._last_fetch_time: float | None = None
        self._min_fetch_interval = 60  # Don't fetch more than once per minute

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self):
        """Close the HTTP client."""
        await self._client.aclose()

    async def get_keys(self) -> dict[str, Any]:
        """
        Get JWKS from cache or fetch from Authentik.

        Returns:
            Dict containing the JWKS data
        """
        cache_key = "jwks"

        # Check cache first
        if cache_key in self._cache:
            logger.debug("Returning JWKS from cache")
            return self._cache[cache_key]

        # Prevent too frequent fetches
        if self._last_fetch_time:
            time_since_last_fetch = time.time() - self._last_fetch_time
            if time_since_last_fetch < self._min_fetch_interval:
                logger.warning(
                    "JWKS fetch requested too soon after previous fetch",
                    time_since_last=time_since_last_fetch
                )
                # Return empty if we're fetching too frequently
                return {"keys": []}

        # Fetch from Authentik
        return await self._fetch_and_cache_keys()

    async def _fetch_and_cache_keys(self) -> dict[str, Any]:
        """Fetch JWKS from Authentik and cache them."""
        try:
            logger.info("Fetching JWKS from Authentik", url=self.config.jwks_url)

            response = await self._client.get(
                self.config.jwks_url,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "nAI-Backend/1.0"
                }
            )
            response.raise_for_status()

            jwks_data = response.json()
            self._last_fetch_time = time.time()

            # Validate the JWKS structure
            if not isinstance(jwks_data, dict) or "keys" not in jwks_data:
                raise ValueError("Invalid JWKS response structure")

            # Cache the result
            self._cache["jwks"] = jwks_data

            logger.info(
                "Successfully fetched and cached JWKS",
                key_count=len(jwks_data.get("keys", []))
            )

            return jwks_data

        except httpx.HTTPStatusError as e:
            logger.error(
                "HTTP error fetching JWKS",
                status_code=e.response.status_code,
                detail=e.response.text
            )
            raise AuthentikError(
                f"Failed to fetch JWKS: HTTP {e.response.status_code}",
                status_code=e.response.status_code
            ) from e

        except Exception as e:
            logger.error("Failed to fetch JWKS", error=str(e))
            raise AuthentikError(f"Failed to fetch JWKS: {str(e)}") from e

    async def get_key_by_kid(self, kid: str) -> dict[str, Any] | None:
        """
        Get a specific key by its key ID (kid).

        Args:
            kid: The key ID to look for

        Returns:
            The key dict if found, None otherwise
        """
        jwks = await self.get_keys()

        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                logger.debug("Found key by kid", kid=kid)
                return key

        logger.warning("Key not found by kid", kid=kid)
        return None

    async def get_signing_key(self, kid: str) -> str | None:
        """
        Get the signing key (public key) for a given kid.

        Args:
            kid: The key ID

        Returns:
            The public key in PEM format if found
        """
        key_data = await self.get_key_by_kid(kid)
        if not key_data:
            return None

        try:
            # Convert JWK to PEM format
            public_key = jwk.construct(key_data)

            # For RSA keys, we need to extract the public key
            if key_data.get("kty") == "RSA":
                pem = public_key.to_pem()
                return pem.decode("utf-8") if isinstance(pem, bytes) else pem

            return None

        except Exception as e:
            logger.error("Failed to construct public key from JWK", error=str(e))
            return None

    async def refresh(self):
        """Force refresh of the JWKS cache."""
        logger.info("Forcing JWKS cache refresh")
        self._cache.clear()
        self._last_fetch_time = None
        await self._fetch_and_cache_keys()

    def clear(self):
        """Clear the cache."""
        self._cache.clear()
        self._last_fetch_time = None
        logger.info("JWKS cache cleared")

    @property
    def is_cached(self) -> bool:
        """Check if JWKS are currently cached."""
        return "jwks" in self._cache

    @property
    def cache_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        return {
            "is_cached": self.is_cached,
            "cache_size": len(self._cache),
            "max_size": self._cache.maxsize,
            "ttl": self._cache.ttl,
            "last_fetch_time": (
                datetime.fromtimestamp(self._last_fetch_time).isoformat()
                if self._last_fetch_time else None
            )
        }
