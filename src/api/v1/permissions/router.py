"""
Permission management API endpoints.
Handles role assignment, resource permissions, and permission checks.
"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ....core.auth.permission_service import PermissionService
from ....core.auth.permissions import PermissionChecker
from ....infrastructure.database.session import get_db
from ...dependencies.context import get_current_user, get_tenant_context
from ...dependencies.permissions import require_permission
from .schemas import (
    PermissionCheckRequest,
    PermissionCheckResponse,
    ResourcePermissionGrant,
    ResourcePermissionResponse,
    Role,
    RoleCreate,
    UserPermissionsResponse,
    UserRoleAssignment,
    UserRoleResponse,
)

router = APIRouter(prefix="/permissions", tags=["permissions"])


@router.get("/roles", response_model=list[Role])
async def list_roles(
    tenant_id: UUID = Depends(get_tenant_context),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
    _: None = Depends(require_permission("role.read"))
):
    """List all roles available in the tenant."""
    service = PermissionService(db)
    return await service.get_tenant_roles(tenant_id)


@router.post("/roles", response_model=Role, status_code=status.HTTP_201_CREATED)
async def create_role(
    role_data: RoleCreate,
    tenant_id: UUID = Depends(get_tenant_context),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
    _: None = Depends(require_permission("role.create"))
):
    """Create a new custom role."""
    service = PermissionService(db)

    try:
        role = await service.create_custom_role(
            tenant_id=tenant_id,
            name=role_data.name,
            description=role_data.description,
            permissions=role_data.permissions,
            created_by=current_user["id"]
        )

        # Return role with permissions
        roles = await service.get_tenant_roles(tenant_id)
        return next((r for r in roles if r["id"] == str(role.id)), None)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/users/{user_id}/roles", response_model=UserRoleResponse)
async def assign_role_to_user(
    user_id: UUID,
    assignment: UserRoleAssignment,
    tenant_id: UUID = Depends(get_tenant_context),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
    _: None = Depends(require_permission("role.assign"))
):
    """Assign a role to a user."""
    service = PermissionService(db)

    try:
        user_role = await service.assign_role_to_user(
            user_id=user_id,
            role_id=assignment.role_id,
            tenant_id=tenant_id,
            granted_by=current_user["id"]
        )

        return UserRoleResponse(
            id=user_role.id,
            user_id=user_role.user_id,
            role_id=user_role.role_id,
            tenant_id=user_role.tenant_id,
            granted_by=user_role.granted_by,
            granted_at=user_role.granted_at
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to assign role: {str(e)}"
        )


@router.delete("/users/{user_id}/roles/{role_id}")
async def remove_role_from_user(
    user_id: UUID,
    role_id: UUID,
    tenant_id: UUID = Depends(get_tenant_context),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
    _: None = Depends(require_permission("role.remove"))
):
    """Remove a role from a user."""
    service = PermissionService(db)

    success = await service.remove_role_from_user(
        user_id=user_id,
        role_id=role_id,
        tenant_id=tenant_id
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role assignment not found"
        )

    return {"message": "Role removed successfully"}


@router.post("/resource", response_model=ResourcePermissionResponse)
async def grant_resource_permission(
    permission_data: ResourcePermissionGrant,
    tenant_id: UUID = Depends(get_tenant_context),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
    _: None = Depends(require_permission("permission.grant"))
):
    """Grant permission on a specific resource to a user or team."""
    if not permission_data.user_id and not permission_data.team_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either user_id or team_id must be provided"
        )

    if permission_data.user_id and permission_data.team_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot grant to both user and team simultaneously"
        )

    service = PermissionService(db)

    resource_permission = await service.grant_resource_permission(
        resource_type=permission_data.resource_type,
        resource_id=permission_data.resource_id,
        permission=permission_data.permission,
        tenant_id=tenant_id,
        granted_by=current_user["id"],
        user_id=permission_data.user_id,
        team_id=permission_data.team_id,
        expires_at=permission_data.expires_at
    )

    return ResourcePermissionResponse(
        id=resource_permission.id,
        resource_type=resource_permission.resource_type,
        resource_id=resource_permission.resource_id,
        user_id=resource_permission.user_id,
        team_id=resource_permission.team_id,
        permission=resource_permission.permission,
        granted_by=resource_permission.granted_by,
        granted_at=resource_permission.granted_at,
        expires_at=resource_permission.expires_at
    )


@router.delete("/resource")
async def revoke_resource_permission(
    permission_data: ResourcePermissionGrant,
    tenant_id: UUID = Depends(get_tenant_context),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
    _: None = Depends(require_permission("permission.revoke"))
):
    """Revoke permission on a specific resource from a user or team."""
    service = PermissionService(db)

    success = await service.revoke_resource_permission(
        resource_type=permission_data.resource_type,
        resource_id=permission_data.resource_id,
        permission=permission_data.permission,
        tenant_id=tenant_id,
        user_id=permission_data.user_id,
        team_id=permission_data.team_id
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resource permission not found"
        )

    return {"message": "Resource permission revoked successfully"}


@router.post("/check", response_model=PermissionCheckResponse)
async def check_permission(
    check_request: PermissionCheckRequest,
    tenant_id: UUID = Depends(get_tenant_context),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Check if current user has a specific permission."""
    checker = PermissionChecker(db)

    has_permission = await checker.check_permission(
        user_id=current_user["id"],
        tenant_id=tenant_id,
        permission=check_request.permission,
        resource_type=check_request.resource_type,
        resource_id=check_request.resource_id
    )

    return PermissionCheckResponse(
        has_permission=has_permission,
        reason=None if has_permission else "Insufficient permissions"
    )


@router.get("/users/me", response_model=UserPermissionsResponse)
async def get_my_permissions(
    tenant_id: UUID = Depends(get_tenant_context),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all permissions for the current user."""
    checker = PermissionChecker(db)
    service = PermissionService(db)

    # Get user roles
    roles_data = await checker.get_user_roles(current_user["id"], tenant_id)

    # Get user permissions
    permissions = await checker.get_user_permissions(current_user["id"], tenant_id)

    # Get resource permissions
    resource_permissions_data = await service.get_user_resource_permissions(
        current_user["id"], tenant_id
    )

    # Convert to response models
    roles = [
        Role(
            id=role["id"],
            tenant_id=tenant_id,
            name=role["name"],
            description=role["description"],
            is_system=role["is_system"],
            permissions=[],  # Not needed in this context
            created_at=current_user.get("created_at"),  # Placeholder
            updated_at=current_user.get("updated_at")   # Placeholder
        )
        for role in roles_data
    ]

    resource_permissions = [
        ResourcePermissionResponse(**rp) for rp in resource_permissions_data
    ]

    return UserPermissionsResponse(
        user_id=current_user["id"],
        tenant_id=tenant_id,
        roles=roles,
        permissions=list(permissions),
        resource_permissions=resource_permissions
    )


@router.get("/users/{user_id}", response_model=UserPermissionsResponse)
async def get_user_permissions(
    user_id: UUID,
    tenant_id: UUID = Depends(get_tenant_context),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
    _: None = Depends(require_permission("user.read"))
):
    """Get all permissions for a specific user (admin only)."""
    checker = PermissionChecker(db)
    service = PermissionService(db)

    # Get user roles
    roles_data = await checker.get_user_roles(user_id, tenant_id)

    # Get user permissions
    permissions = await checker.get_user_permissions(user_id, tenant_id)

    # Get resource permissions
    resource_permissions_data = await service.get_user_resource_permissions(
        user_id, tenant_id
    )

    # Convert to response models
    roles = [
        Role(
            id=role["id"],
            tenant_id=tenant_id,
            name=role["name"],
            description=role["description"],
            is_system=role["is_system"],
            permissions=[],  # Not needed in this context
            created_at=current_user.get("created_at"),  # Placeholder
            updated_at=current_user.get("updated_at")   # Placeholder
        )
        for role in roles_data
    ]

    resource_permissions = [
        ResourcePermissionResponse(**rp) for rp in resource_permissions_data
    ]

    return UserPermissionsResponse(
        user_id=user_id,
        tenant_id=tenant_id,
        roles=roles,
        permissions=list(permissions),
        resource_permissions=resource_permissions
    )
