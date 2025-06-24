"""
Permission-based authorization dependencies for FastAPI endpoints.
Provides fine-grained access control based on user permissions.
Updated to use the new permission system from task-130.
"""
from typing import Callable, List, Optional, Set
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ...core.auth.permissions import PermissionChecker
from ...infrastructure.database.session import get_db
from .context import get_current_user, get_tenant_context
from ...core.logging import get_logger

logger = get_logger(__name__)


def _get_user_permissions(request: Request) -> Set[str]:
    """
    Extract user permissions from request state.
    
    Args:
        request: The FastAPI request object
        
    Returns:
        Set[str]: Set of user permissions
    """
    # Get permissions from request state (set by JWT middleware)
    permissions = getattr(request.state, "permissions", [])
    
    # Also check groups for group-based permissions
    groups = getattr(request.state, "groups", [])
    
    # Convert to set for efficient lookups
    permission_set = set(permissions)
    
    # Add any group-based permissions (if implementing group->permission mapping)
    # This is where you'd expand groups to their associated permissions
    
    return permission_set


def _check_permission(
    user_permissions: Set[str],
    required_permission: str,
    user_id: str,
) -> bool:
    """
    Check if user has the required permission.
    
    Args:
        user_permissions: Set of user permissions
        required_permission: The required permission
        user_id: User ID for logging
        
    Returns:
        bool: True if user has permission
    """
    # Check exact match
    if required_permission in user_permissions:
        return True
    
    # Check wildcard permissions (e.g., "admin:*" matches "admin:read")
    permission_parts = required_permission.split(":")
    for i in range(len(permission_parts)):
        wildcard = ":".join(permission_parts[:i+1] + ["*"])
        if wildcard in user_permissions:
            logger.debug(
                "Permission granted via wildcard",
                user_id=user_id,
                required=required_permission,
                wildcard=wildcard
            )
            return True
    
    # Check if user has superuser/admin permission
    if "admin" in user_permissions or "superuser" in user_permissions:
        logger.debug(
            "Permission granted via admin privileges",
            user_id=user_id,
            required=required_permission
        )
        return True
    
    return False


def require_permission(permission: str, resource_type: Optional[str] = None) -> Callable:
    """
    Create a dependency that requires a specific permission.
    Uses the new permission system from task-130.
    
    Args:
        permission: Required permission (e.g., 'conversation.create')
        resource_type: Optional resource type for resource-level checks
        
    Returns:
        FastAPI dependency function
    """
    async def permission_dependency(
        current_user: dict = Depends(get_current_user),
        tenant_id: UUID = Depends(get_tenant_context),
        db: Session = Depends(get_db)
    ) -> None:
        """Check if current user has the required permission."""
        checker = PermissionChecker(db)
        
        has_permission = await checker.check_permission(
            user_id=current_user["id"],
            tenant_id=tenant_id,
            permission=permission,
            resource_type=resource_type
        )
        
        if not has_permission:
            logger.warning(
                "Permission denied",
                user_id=str(current_user["id"]),
                tenant_id=str(tenant_id),
                required_permission=permission,
                resource_type=resource_type
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {permission}"
            )
        
        logger.debug(
            "Permission granted",
            user_id=str(current_user["id"]),
            permission=permission
        )
    
    return permission_dependency


def require_any_permission(permissions: List[str]):
    """
    Create a dependency that requires at least one of the specified permissions.
    
    Args:
        permissions: List of permissions (user needs at least one)
        
    Returns:
        Dependency function that validates the permissions
    """
    async def check_any_permission(
        request: Request,
        current_user: User = Depends(get_current_user),
    ) -> User:
        """Check if the current user has any of the required permissions."""
        user_permissions = _get_user_permissions(request)
        
        for permission in permissions:
            if _check_permission(user_permissions, permission, str(current_user.id)):
                logger.debug(
                    "Permission granted (any)",
                    user_id=str(current_user.id),
                    granted_permission=permission,
                    required_permissions=permissions
                )
                return current_user
        
        logger.warning(
            "All permissions denied",
            user_id=str(current_user.id),
            required_permissions=permissions,
            user_permissions=list(user_permissions)
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"One of these permissions required: {', '.join(permissions)}",
        )
    
    return check_any_permission


def require_all_permissions(permissions: List[str]):
    """
    Create a dependency that requires all of the specified permissions.
    
    Args:
        permissions: List of permissions (user needs all)
        
    Returns:
        Dependency function that validates the permissions
    """
    async def check_all_permissions(
        request: Request,
        current_user: User = Depends(get_current_user),
    ) -> User:
        """Check if the current user has all of the required permissions."""
        user_permissions = _get_user_permissions(request)
        missing_permissions = []
        
        for permission in permissions:
            if not _check_permission(user_permissions, permission, str(current_user.id)):
                missing_permissions.append(permission)
        
        if missing_permissions:
            logger.warning(
                "Some permissions denied",
                user_id=str(current_user.id),
                required_permissions=permissions,
                missing_permissions=missing_permissions,
                user_permissions=list(user_permissions)
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"All of these permissions required: {', '.join(permissions)}. Missing: {', '.join(missing_permissions)}",
            )
        
        logger.debug(
            "All permissions granted",
            user_id=str(current_user.id),
            permissions=permissions
        )
        return current_user
    
    return check_all_permissions


def require_tenant_permission(permission: str):
    """
    Create a dependency that requires a permission within the tenant context.
    This combines tenant membership validation with permission checking.
    
    Args:
        permission: The required permission
        
    Returns:
        Dependency function that validates tenant membership and permission
    """
    async def check_tenant_permission(
        request: Request,
        tenant_user: TenantUser = Depends(get_tenant_user),
    ) -> TenantUser:
        """Check if user has the required permission in the tenant context."""
        # Get base permissions from JWT
        user_permissions = _get_user_permissions(request)
        
        # Add tenant-specific permissions
        tenant_permissions = set(tenant_user.permissions) if tenant_user.permissions else set()
        
        # Add role-based permissions
        role_permissions = _get_role_permissions(tenant_user.role)
        
        # Combine all permissions
        all_permissions = user_permissions | tenant_permissions | role_permissions
        
        if not _check_permission(all_permissions, permission, str(tenant_user.user_id)):
            logger.warning(
                "Tenant permission denied",
                user_id=str(tenant_user.user_id),
                tenant_id=str(tenant_user.tenant_id),
                required_permission=permission,
                role=tenant_user.role,
                permissions=list(all_permissions)
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' required in this tenant",
            )
        
        logger.debug(
            "Tenant permission granted",
            user_id=str(tenant_user.user_id),
            tenant_id=str(tenant_user.tenant_id),
            permission=permission
        )
        return tenant_user
    
    return check_tenant_permission


def _get_role_permissions(role: str) -> Set[str]:
    """
    Get permissions associated with a tenant role.
    
    Args:
        role: The tenant role (owner, admin, member, viewer)
        
    Returns:
        Set[str]: Permissions for the role
    """
    # Define role-based permissions
    # This is a simple example - in production, this might come from a database
    role_permissions = {
        "owner": {
            "tenant:*",  # All tenant permissions
            "users:*",   # All user management
            "teams:*",   # All team management
            "billing:*", # Billing access
        },
        "admin": {
            "tenant:read",
            "tenant:update",
            "users:*",
            "teams:*",
            "agents:*",
            "conversations:*",
        },
        "member": {
            "tenant:read",
            "users:read",
            "teams:read",
            "teams:update:own",  # Can update own team
            "agents:*",
            "conversations:*",
        },
        "viewer": {
            "tenant:read",
            "users:read",
            "teams:read",
            "agents:read",
            "conversations:read",
        },
    }
    
    return role_permissions.get(role, set())


def has_permission(
    permission: str,
    request: Request,
    user: User,
) -> bool:
    """
    Check if a user has a specific permission without raising an exception.
    Useful for conditional logic in endpoints.
    
    Args:
        permission: The permission to check
        request: The FastAPI request object
        user: The user to check
        
    Returns:
        bool: True if user has permission, False otherwise
    """
    user_permissions = _get_user_permissions(request)
    return _check_permission(user_permissions, permission, str(user.id))