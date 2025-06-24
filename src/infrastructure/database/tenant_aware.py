"""Tenant-aware database utilities that integrate with tenant context."""
from typing import Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from src.core.context import get_tenant_context, require_tenant_context
from src.core.logging import get_logger
from src.infrastructure.database.unit_of_work import UnitOfWork

logger = get_logger(__name__)


async def get_tenant_aware_unit_of_work(
    session: AsyncSession,
    tenant_id: Optional[UUID | str] = None
) -> UnitOfWork:
    """Create a UnitOfWork instance with tenant context.
    
    If no tenant_id is provided, it will attempt to get it from the context.
    
    Args:
        session: Database session
        tenant_id: Optional tenant ID. If not provided, uses context.
        
    Returns:
        UnitOfWork instance configured for the tenant
        
    Raises:
        RuntimeError: If no tenant context is available when required
    """
    if tenant_id is None:
        # Try to get from context
        context_tenant_id = get_tenant_context()
        if context_tenant_id:
            tenant_id = UUID(context_tenant_id)
            logger.debug("Using tenant from context", tenant_id=tenant_id)
        else:
            # If multi-tenancy is enabled, tenant is required
            from src.core.config import settings
            if settings.ENABLE_MULTI_TENANCY:
                # This will raise RuntimeError if no context
                context_tenant_id = require_tenant_context()
                tenant_id = UUID(context_tenant_id)
            else:
                # Single tenant mode - use default
                tenant_id = UUID(settings.DEFAULT_TENANT_ID) if settings.DEFAULT_TENANT_ID else None
    else:
        # Convert to UUID if string
        if isinstance(tenant_id, str):
            tenant_id = UUID(tenant_id)
    
    return UnitOfWork(session, tenant_id)


class TenantAwareRepositoryMixin:
    """Mixin to make repositories automatically use tenant context.
    
    This mixin can be added to repository classes to automatically
    filter queries by the current tenant context.
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Check if this is a tenant-aware repository
        if hasattr(self, 'tenant_id') and self.tenant_id is None:
            # Try to get tenant from context
            context_tenant_id = get_tenant_context()
            if context_tenant_id:
                self.tenant_id = UUID(context_tenant_id)
                logger.debug(
                    "Repository using tenant from context",
                    repository=self.__class__.__name__,
                    tenant_id=self.tenant_id
                )