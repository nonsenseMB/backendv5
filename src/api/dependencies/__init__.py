"""FastAPI dependencies for authentication, authorization, and context management."""

from .auth import get_current_user, get_optional_user, require_auth
from .permissions import require_all_permissions, require_any_permission, require_permission
from .session import get_current_session, get_optional_session
from .tenant import get_current_tenant, require_tenant

__all__ = [
    # Auth dependencies
    "get_current_user",
    "require_auth",
    "get_optional_user",
    # Permission dependencies
    "require_permission",
    "require_any_permission",
    "require_all_permissions",
    # Session dependencies
    "get_current_session",
    "get_optional_session",
    # Tenant dependencies
    "get_current_tenant",
    "require_tenant",
]
