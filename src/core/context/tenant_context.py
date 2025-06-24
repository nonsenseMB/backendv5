"""Tenant context management using contextvars for thread-safe isolation."""
from contextvars import ContextVar
from uuid import UUID

from src.core.logging import get_logger

logger = get_logger(__name__)

# Thread-safe context variable for tenant ID
tenant_context: ContextVar[str | None] = ContextVar('tenant_context', default=None)


def set_tenant_context(tenant_id: str | UUID) -> None:
    """Set the current tenant context.
    
    Args:
        tenant_id: The tenant ID to set in the context
    """
    tenant_id_str = str(tenant_id) if isinstance(tenant_id, UUID) else tenant_id
    tenant_context.set(tenant_id_str)
    logger.debug("Tenant context set", tenant_id=tenant_id_str)


def get_tenant_context() -> str | None:
    """Get the current tenant context.
    
    Returns:
        The current tenant ID or None if not set
    """
    return tenant_context.get()


def clear_tenant_context() -> None:
    """Clear the current tenant context."""
    tenant_context.set(None)
    logger.debug("Tenant context cleared")


def require_tenant_context() -> str:
    """Get the current tenant context, raising an error if not set.
    
    Returns:
        The current tenant ID
        
    Raises:
        RuntimeError: If no tenant context is set
    """
    tenant_id = get_tenant_context()
    if not tenant_id:
        raise RuntimeError("No tenant context set. This operation requires a tenant.")
    return tenant_id


class TenantContextManager:
    """Context manager for temporarily setting tenant context."""

    def __init__(self, tenant_id: str | UUID):
        self.tenant_id = str(tenant_id) if isinstance(tenant_id, UUID) else tenant_id
        self.previous_tenant = None

    def __enter__(self):
        """Store previous tenant and set new one."""
        self.previous_tenant = get_tenant_context()
        set_tenant_context(self.tenant_id)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Restore previous tenant context."""
        if self.previous_tenant:
            set_tenant_context(self.previous_tenant)
        else:
            clear_tenant_context()
