"""
Core permission system for role-based and resource-based access control.
Implements the permission model defined in task-130.
"""

from enum import Enum
from uuid import UUID

from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from ...infrastructure.database.models.permission import Permission, ResourcePermission, Role, RolePermission, UserRole


class SystemRole(str, Enum):
    """System-defined roles with predefined permissions."""
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


# System roles with their default permissions
SYSTEM_ROLE_PERMISSIONS: dict[SystemRole, list[str]] = {
    SystemRole.ADMIN: [
        "tenant.manage",
        "user.manage",
        "conversation.*",
        "document.*",
        "agent.*",
        "tool.*",
        "memory.*",
        "team.*",
        "role.*",
    ],
    SystemRole.MEMBER: [
        "conversation.create",
        "conversation.read",
        "conversation.update",
        "document.create",
        "document.read",
        "document.update",
        "agent.use",
        "memory.read",
        "team.read",
    ],
    SystemRole.VIEWER: [
        "conversation.read",
        "document.read",
        "agent.read",
        "memory.read",
        "team.read",
    ]
}


class PermissionChecker:
    """Core permission checking logic."""

    def __init__(self, db: Session):
        self.db = db

    async def check_permission(
        self,
        user_id: UUID,
        tenant_id: UUID,
        permission: str,
        resource_type: str | None = None,
        resource_id: UUID | None = None
    ) -> bool:
        """
        Check if user has permission within tenant.
        
        Args:
            user_id: User ID
            tenant_id: Tenant ID
            permission: Permission string (e.g., 'conversation.create')
            resource_type: Optional resource type for resource-level checks
            resource_id: Optional resource ID for resource-level checks
            
        Returns:
            True if user has permission, False otherwise
        """
        # First check role-based permissions
        if await self._check_role_permission(user_id, tenant_id, permission):
            return True

        # Then check resource-specific permissions if resource provided
        if resource_type and resource_id:
            return await self._check_resource_permission(
                user_id, tenant_id, resource_type, resource_id, permission
            )

        return False

    async def _check_role_permission(self, user_id: UUID, tenant_id: UUID, permission: str) -> bool:
        """Check if user has permission through their roles."""
        # Handle wildcard permissions (e.g., 'conversation.*' matches 'conversation.create')
        resource_wildcard = f"{permission.split('.')[0]}.*"

        query = (
            self.db.query(Permission)
            .join(RolePermission, Permission.id == RolePermission.permission_id)
            .join(Role, RolePermission.role_id == Role.id)
            .join(UserRole, Role.id == UserRole.role_id)
            .filter(
                and_(
                    UserRole.user_id == user_id,
                    UserRole.tenant_id == tenant_id,
                    or_(
                        Permission.name == permission,
                        Permission.name == resource_wildcard
                    )
                )
            )
        )

        return query.first() is not None

    async def _check_resource_permission(
        self,
        user_id: UUID,
        tenant_id: UUID,
        resource_type: str,
        resource_id: UUID,
        permission: str
    ) -> bool:
        """Check resource-specific permissions."""
        # Extract action from permission (e.g., 'create' from 'conversation.create')
        action = permission.split('.')[-1]

        # Check direct user permissions
        user_permission = (
            self.db.query(ResourcePermission)
            .filter(
                and_(
                    ResourcePermission.tenant_id == tenant_id,
                    ResourcePermission.user_id == user_id,
                    ResourcePermission.resource_type == resource_type,
                    ResourcePermission.resource_id == resource_id,
                    ResourcePermission.permission == action
                )
            )
            .first()
        )

        if user_permission:
            return True

        # Check team permissions with proper team membership validation
        from ...infrastructure.database.models.team import TeamMember

        team_permission = (
            self.db.query(ResourcePermission)
            .join(TeamMember, ResourcePermission.team_id == TeamMember.team_id)
            .filter(
                and_(
                    ResourcePermission.tenant_id == tenant_id,
                    ResourcePermission.team_id.isnot(None),
                    ResourcePermission.resource_type == resource_type,
                    ResourcePermission.resource_id == resource_id,
                    ResourcePermission.permission == action,
                    TeamMember.user_id == user_id,
                    TeamMember.is_active == True
                )
            )
            .first()
        )

        return team_permission is not None

    async def get_user_permissions(self, user_id: UUID, tenant_id: UUID) -> set[str]:
        """Get all permissions for a user within a tenant."""
        permissions = set()

        # Get role-based permissions
        role_permissions = (
            self.db.query(Permission.name)
            .join(RolePermission, Permission.id == RolePermission.permission_id)
            .join(Role, RolePermission.role_id == Role.id)
            .join(UserRole, Role.id == UserRole.role_id)
            .filter(
                and_(
                    UserRole.user_id == user_id,
                    UserRole.tenant_id == tenant_id
                )
            )
            .all()
        )

        for (perm_name,) in role_permissions:
            permissions.add(perm_name)

        return permissions

    async def get_user_roles(self, user_id: UUID, tenant_id: UUID) -> list[dict]:
        """Get all roles for a user within a tenant."""
        roles = (
            self.db.query(Role)
            .join(UserRole, Role.id == UserRole.role_id)
            .filter(
                and_(
                    UserRole.user_id == user_id,
                    UserRole.tenant_id == tenant_id
                )
            )
            .all()
        )

        return [
            {
                "id": str(role.id),
                "name": role.name,
                "description": role.description,
                "is_system": role.is_system
            }
            for role in roles
        ]


class TenantPermissionValidator:
    """Validates tenant isolation for permissions."""

    def __init__(self, db: Session):
        self.db = db

    async def validate_tenant_access(
        self,
        user_id: UUID,
        tenant_id: UUID,
        resource_type: str | None = None,
        resource_id: UUID | None = None
    ) -> bool:
        """
        Validate that user has access to tenant and resource belongs to tenant.
        
        Args:
            user_id: User ID
            tenant_id: Tenant ID  
            resource_type: Optional resource type
            resource_id: Optional resource ID
            
        Returns:
            True if access is valid, False otherwise
        """
        # Check if user belongs to tenant
        from ...infrastructure.database.models.tenant import TenantUser

        tenant_user = (
            self.db.query(TenantUser)
            .filter(
                and_(
                    TenantUser.user_id == user_id,
                    TenantUser.tenant_id == tenant_id,
                    TenantUser.is_active == True
                )
            )
            .first()
        )

        if not tenant_user:
            return False

        # If resource provided, verify it belongs to tenant
        if resource_type and resource_id:
            return await self._verify_resource_tenant(resource_type, resource_id, tenant_id)

        return True

    async def _verify_resource_tenant(
        self, resource_type: str, resource_id: UUID, tenant_id: UUID
    ) -> bool:
        """Verify that resource belongs to the specified tenant."""
        # Map resource types to their models
        resource_models = {
            "conversation": "Conversation",
            "document": "Document",
            "agent": "Agent",
            "team": "Team",
            # Add more as needed
        }

        if resource_type not in resource_models:
            return False

        # For now, assume all resources have tenant_id field
        # In a real implementation, you'd dynamically query the appropriate model
        return True  # Placeholder - implement actual checking


def apply_tenant_filter(query, tenant_id: UUID, model_class):
    """Apply tenant filter to SQLAlchemy query."""
    if hasattr(model_class, 'tenant_id'):
        return query.filter(model_class.tenant_id == tenant_id)
    return query


# Route permission mapping is now handled in the middleware module
# to avoid circular imports and keep it centralized
