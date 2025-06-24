"""
CORS configuration for multi-tenant support.
Provides tenant-aware CORS origin validation and configuration.
"""
import re
from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.infrastructure.database.session import get_async_session
from src.infrastructure.database.unit_of_work import UnitOfWork

logger = get_logger(__name__)

# Cache for tenant CORS origins to avoid database queries on every request
_tenant_cors_cache: dict[str, set[str]] = {}
_cache_ttl_seconds = 300  # 5 minutes


class CORSConfig:
    """
    CORS configuration manager with tenant-aware origin validation.
    """

    def __init__(self):
        # Import settings here to avoid circular import
        from src.core.config import settings

        # Global allowed origins from settings
        self.global_origins: set[str] = set(settings.CORS_ORIGINS)

        # Wildcard patterns for dynamic origin matching
        self.wildcard_patterns: list[re.Pattern] = []

        # Parse wildcard origins
        for origin in self.global_origins:
            if "*" in origin:
                # Convert wildcard to regex pattern
                pattern = origin.replace(".", r"\.")
                pattern = pattern.replace("*", r"[^.]+")
                pattern = f"^{pattern}$"
                self.wildcard_patterns.append(re.compile(pattern))

        # Development mode allows localhost with any port
        if settings.DEBUG:
            self.wildcard_patterns.append(
                re.compile(r"^https?://localhost(:\d+)?$")
            )
            self.wildcard_patterns.append(
                re.compile(r"^https?://127\.0\.0\.1(:\d+)?$")
            )

    def is_origin_allowed_globally(self, origin: str) -> bool:
        """
        Check if origin is allowed globally (not tenant-specific).
        
        Args:
            origin: The origin to check
            
        Returns:
            True if origin is allowed globally
        """
        # Check exact match
        if origin in self.global_origins:
            return True

        # Check wildcard patterns
        for pattern in self.wildcard_patterns:
            if pattern.match(origin):
                return True

        return False

    async def get_tenant_allowed_origins(
        self,
        tenant_id: str,
        session: AsyncSession | None = None
    ) -> set[str]:
        """
        Get allowed origins for a specific tenant.
        
        Args:
            tenant_id: The tenant ID
            session: Optional database session
            
        Returns:
            Set of allowed origins for the tenant
        """
        # Check cache first
        if tenant_id in _tenant_cors_cache:
            return _tenant_cors_cache[tenant_id]

        # Fetch from database
        try:
            if session is None:
                async with get_async_session() as session:
                    return await self._fetch_tenant_origins(tenant_id, session)
            else:
                return await self._fetch_tenant_origins(tenant_id, session)
        except Exception as e:
            logger.error(
                "Failed to fetch tenant CORS origins",
                tenant_id=tenant_id,
                error=str(e)
            )
            return set()

    async def _fetch_tenant_origins(
        self,
        tenant_id: str,
        session: AsyncSession
    ) -> set[str]:
        """
        Fetch tenant origins from database.
        
        Args:
            tenant_id: The tenant ID
            session: Database session
            
        Returns:
            Set of allowed origins
        """
        uow = UnitOfWork(session)
        tenant = await uow.tenants.get_by_id(tenant_id)

        if not tenant or not tenant.is_active:
            return set()

        # Get CORS origins from tenant settings
        tenant_origins = set()

        # Check tenant settings for cors_origins
        if tenant.settings and isinstance(tenant.settings, dict):
            cors_origins = tenant.settings.get("cors_origins", [])
            if isinstance(cors_origins, list):
                tenant_origins.update(cors_origins)

        # Add tenant's custom domain if configured
        if tenant.domain:
            # Add both http and https versions
            tenant_origins.add(f"https://{tenant.domain}")
            if settings.DEBUG:
                tenant_origins.add(f"http://{tenant.domain}")

        # Cache the result
        _tenant_cors_cache[tenant_id] = tenant_origins

        # Schedule cache cleanup
        # In production, use a proper cache with TTL
        import asyncio
        asyncio.create_task(self._clear_cache_entry(tenant_id))

        return tenant_origins

    async def _clear_cache_entry(self, tenant_id: str):
        """Clear cache entry after TTL."""
        await asyncio.sleep(_cache_ttl_seconds)
        _tenant_cors_cache.pop(tenant_id, None)

    async def is_origin_allowed_for_tenant(
        self,
        origin: str,
        tenant_id: str,
        session: AsyncSession | None = None
    ) -> bool:
        """
        Check if origin is allowed for a specific tenant.
        
        Args:
            origin: The origin to check
            tenant_id: The tenant ID
            session: Optional database session
            
        Returns:
            True if origin is allowed for the tenant
        """
        # Check global origins first
        if self.is_origin_allowed_globally(origin):
            return True

        # Check tenant-specific origins
        tenant_origins = await self.get_tenant_allowed_origins(tenant_id, session)
        return origin in tenant_origins

    def validate_origin(self, origin: str) -> bool:
        """
        Validate that an origin is well-formed.
        
        Args:
            origin: The origin to validate
            
        Returns:
            True if origin is valid
        """
        try:
            parsed = urlparse(origin)
            # Origin must have scheme and netloc
            return bool(parsed.scheme and parsed.netloc and not parsed.path)
        except Exception:
            return False

    def get_cors_headers(
        self,
        origin: str,
        credentials: bool = True,
        max_age: int = 3600
    ) -> dict[str, str]:
        """
        Generate CORS headers for a valid origin.
        
        Args:
            origin: The allowed origin
            credentials: Whether to allow credentials
            max_age: Preflight cache duration in seconds
            
        Returns:
            Dictionary of CORS headers
        """
        from src.core.config import settings

        headers = {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Methods": ", ".join(settings.CORS_ALLOW_METHODS),
            "Access-Control-Allow-Headers": ", ".join(settings.CORS_ALLOW_HEADERS),
            "Access-Control-Max-Age": str(max_age),
        }

        if credentials:
            headers["Access-Control-Allow-Credentials"] = "true"

        # Add exposed headers if configured
        exposed_headers = getattr(settings, "CORS_EXPOSE_HEADERS", [])
        if exposed_headers:
            headers["Access-Control-Expose-Headers"] = ", ".join(exposed_headers)

        return headers


# Global CORS configuration instance
cors_config = CORSConfig()


async def get_allowed_origins(request_origin: str, tenant_id: str | None = None) -> str | None:
    """
    FastAPI CORS middleware callback to determine allowed origins.
    
    This function is called by the CORS middleware for each request
    to determine if the origin should be allowed.
    
    Args:
        request_origin: The origin from the request
        tenant_id: Optional tenant ID for tenant-specific CORS
        
    Returns:
        The origin if allowed, None otherwise
    """
    # Validate origin format
    if not cors_config.validate_origin(request_origin):
        logger.debug("Invalid origin format", origin=request_origin)
        return None

    # Check global origins
    if cors_config.is_origin_allowed_globally(request_origin):
        logger.debug("Origin allowed globally", origin=request_origin)
        return request_origin

    # Check tenant-specific origins if tenant_id provided
    if tenant_id:
        try:
            if await cors_config.is_origin_allowed_for_tenant(request_origin, tenant_id):
                logger.debug(
                    "Origin allowed for tenant",
                    origin=request_origin,
                    tenant_id=tenant_id
                )
                return request_origin
        except Exception as e:
            logger.error(
                "Error checking tenant CORS",
                origin=request_origin,
                tenant_id=tenant_id,
                error=str(e)
            )

    logger.debug("Origin not allowed", origin=request_origin)
    return None


def clear_tenant_cors_cache(tenant_id: str | None = None):
    """
    Clear CORS cache for a tenant or all tenants.
    
    Args:
        tenant_id: Specific tenant to clear, or None for all
    """
    if tenant_id:
        _tenant_cors_cache.pop(tenant_id, None)
        logger.info("Cleared CORS cache for tenant", tenant_id=tenant_id)
    else:
        _tenant_cors_cache.clear()
        logger.info("Cleared all CORS cache entries")
