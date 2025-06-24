"""Core context management for request-scoped data."""
from .request_context import (
    RequestContext,
    RequestContextManager,
    clear_request_context,
    create_request_id,
    get_request_context,
    require_request_context,
    set_request_context,
    update_request_context,
)
from .tenant_context import (
    TenantContextManager,
    clear_tenant_context,
    get_tenant_context,
    require_tenant_context,
    set_tenant_context,
    tenant_context,
)
from .user_context import (
    UserContext,
    UserContextManager,
    clear_user_context,
    get_user_context,
    require_user_context,
    set_user_context,
    update_user_context,
)

__all__ = [
    # Request context
    "RequestContext",
    "RequestContextManager",
    "set_request_context",
    "get_request_context",
    "clear_request_context",
    "require_request_context",
    "update_request_context",
    "create_request_id",
    # Tenant context
    "tenant_context",
    "set_tenant_context",
    "get_tenant_context",
    "clear_tenant_context",
    "require_tenant_context",
    "TenantContextManager",
    # User context
    "UserContext",
    "UserContextManager",
    "set_user_context",
    "get_user_context",
    "clear_user_context",
    "require_user_context",
    "update_user_context",
]
