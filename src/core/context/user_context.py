"""User-specific context management."""
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from src.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class UserContext:
    """
    User-specific context information.
    
    This dataclass holds user-specific information that may be needed
    across different parts of the application.
    """
    # Core user information
    user_id: UUID
    email: str
    username: Optional[str] = None
    full_name: Optional[str] = None
    
    # User status
    is_active: bool = True
    is_verified: bool = False
    is_superuser: bool = False
    
    # Authentication details
    auth_provider: Optional[str] = None  # e.g., "authentik", "internal"
    external_id: Optional[str] = None    # External provider user ID
    
    # User permissions and roles
    permissions: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    tenant_roles: Dict[str, str] = field(default_factory=dict)  # tenant_id -> role
    
    # User preferences
    language: str = "en"
    timezone: str = "UTC"
    theme: str = "light"
    
    # Activity tracking
    last_login: Optional[datetime] = None
    last_activity: Optional[datetime] = None
    login_count: int = 0
    
    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def has_permission(self, permission: str) -> bool:
        """
        Check if user has a specific permission.
        
        Args:
            permission: The permission to check
            
        Returns:
            True if user has the permission
        """
        # Check exact match
        if permission in self.permissions:
            return True
        
        # Check wildcard permissions
        permission_parts = permission.split(":")
        for i in range(len(permission_parts)):
            wildcard = ":".join(permission_parts[:i+1] + ["*"])
            if wildcard in self.permissions:
                return True
        
        # Check superuser
        if self.is_superuser or "admin" in self.permissions:
            return True
        
        return False
    
    def has_any_permission(self, permissions: List[str]) -> bool:
        """Check if user has any of the specified permissions."""
        return any(self.has_permission(p) for p in permissions)
    
    def has_all_permissions(self, permissions: List[str]) -> bool:
        """Check if user has all of the specified permissions."""
        return all(self.has_permission(p) for p in permissions)
    
    def get_tenant_role(self, tenant_id: str) -> Optional[str]:
        """Get user's role in a specific tenant."""
        return self.tenant_roles.get(str(tenant_id))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary for serialization."""
        return {
            "user_id": str(self.user_id),
            "email": self.email,
            "username": self.username,
            "full_name": self.full_name,
            "is_active": self.is_active,
            "is_verified": self.is_verified,
            "is_superuser": self.is_superuser,
            "auth_provider": self.auth_provider,
            "permissions": self.permissions,
            "groups": self.groups,
            "tenant_roles": self.tenant_roles,
            "language": self.language,
            "timezone": self.timezone,
            "theme": self.theme,
            **self.metadata
        }


# Thread-safe context variable
_user_context: ContextVar[Optional[UserContext]] = ContextVar(
    "user_context", default=None
)


def get_user_context() -> Optional[UserContext]:
    """
    Get the current user context.
    
    Returns:
        The current UserContext or None if not set
    """
    return _user_context.get()


def set_user_context(context: UserContext) -> None:
    """
    Set the user context.
    
    Args:
        context: The UserContext to set
    """
    _user_context.set(context)
    logger.debug(
        "User context set",
        user_id=str(context.user_id),
        email=context.email,
        permissions_count=len(context.permissions)
    )


def clear_user_context() -> None:
    """Clear the user context."""
    context = get_user_context()
    if context:
        logger.debug(
            "User context cleared",
            user_id=str(context.user_id)
        )
    _user_context.set(None)


def require_user_context() -> UserContext:
    """
    Get the current user context, raising an error if not set.
    
    Returns:
        The current UserContext
        
    Raises:
        RuntimeError: If no user context is set
    """
    context = get_user_context()
    if not context:
        raise RuntimeError("No user context set. This operation requires an authenticated user.")
    return context


class UserContextManager:
    """
    Context manager for temporarily setting user context.
    
    This is useful for background tasks or when you need to temporarily
    switch user context.
    """
    
    def __init__(self, context: UserContext):
        self.context = context
        self.previous_context: Optional[UserContext] = None
    
    def __enter__(self):
        """Store previous context and set new one."""
        self.previous_context = get_user_context()
        set_user_context(self.context)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Restore previous context."""
        if self.previous_context:
            set_user_context(self.previous_context)
        else:
            clear_user_context()


def update_user_context(**kwargs) -> None:
    """
    Update fields in the current user context.
    
    Args:
        **kwargs: Fields to update in the context
        
    Raises:
        RuntimeError: If no user context is set
    """
    context = require_user_context()
    
    for key, value in kwargs.items():
        if hasattr(context, key):
            setattr(context, key, value)
        else:
            # Store unknown fields in metadata
            context.metadata[key] = value
    
    logger.debug(
        "User context updated",
        user_id=str(context.user_id),
        updates=list(kwargs.keys())
    )