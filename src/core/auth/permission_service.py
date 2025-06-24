"""
Permission service for managing roles and permissions.
Provides high-level operations for the permission system.
"""

from uuid import UUID

from sqlalchemy import and_
from sqlalchemy.orm import Session

from ...infrastructure.database.models.permission import Permission, ResourcePermission, Role, RolePermission, UserRole
from .permissions import SYSTEM_ROLE_PERMISSIONS, SystemRole


class PermissionService:
    """Service for managing permissions, roles, and assignments."""

    def __init__(self, db: Session):
        self.db = db

    async def create_system_roles(self, tenant_id: UUID) -> list[Role]:
        """Create system roles for a tenant."""
        created_roles = []

        for system_role in SystemRole:
            # Check if role already exists
            existing_role = (
                self.db.query(Role)
                .filter(
                    and_(
                        Role.tenant_id == tenant_id,
                        Role.name == system_role.value,
                        Role.is_system == True
                    )
                )
                .first()
            )

            if existing_role:
                created_roles.append(existing_role)
                continue

            # Create the role
            role = Role(
                tenant_id=tenant_id,
                name=system_role.value,
                description=f"System {system_role.value.title()} role",
                is_system=True
            )
            self.db.add(role)
            self.db.flush()  # Get the ID

            # Add permissions to the role
            permissions = SYSTEM_ROLE_PERMISSIONS[system_role]
            for permission_name in permissions:
                await self._add_permission_to_role(role.id, permission_name)

            created_roles.append(role)

        self.db.commit()
        return created_roles

    async def _add_permission_to_role(self, role_id: UUID, permission_name: str) -> None:
        """Add a permission to a role."""
        # Get or create permission
        permission = (
            self.db.query(Permission)
            .filter(Permission.name == permission_name)
            .first()
        )

        if not permission:
            # Extract resource and action from permission name
            if '.' in permission_name:
                resource, action = permission_name.split('.', 1)
            else:
                resource = permission_name
                action = 'all'

            permission = Permission(
                name=permission_name,
                resource=resource,
                action=action,
                description=f"Permission to {action} {resource}"
            )
            self.db.add(permission)
            self.db.flush()

        # Check if role-permission already exists
        existing = (
            self.db.query(RolePermission)
            .filter(
                and_(
                    RolePermission.role_id == role_id,
                    RolePermission.permission_id == permission.id
                )
            )
            .first()
        )

        if not existing:
            role_permission = RolePermission(
                role_id=role_id,
                permission_id=permission.id
            )
            self.db.add(role_permission)

    async def assign_role_to_user(
        self,
        user_id: UUID,
        role_id: UUID,
        tenant_id: UUID,
        granted_by: UUID
    ) -> UserRole:
        """Assign a role to a user within a tenant."""
        # Check if assignment already exists
        existing = (
            self.db.query(UserRole)
            .filter(
                and_(
                    UserRole.user_id == user_id,
                    UserRole.role_id == role_id,
                    UserRole.tenant_id == tenant_id
                )
            )
            .first()
        )

        if existing:
            return existing

        # Create new assignment
        user_role = UserRole(
            user_id=user_id,
            role_id=role_id,
            tenant_id=tenant_id,
            granted_by=granted_by
        )

        self.db.add(user_role)
        self.db.commit()
        return user_role

    async def remove_role_from_user(
        self,
        user_id: UUID,
        role_id: UUID,
        tenant_id: UUID
    ) -> bool:
        """Remove a role from a user within a tenant."""
        user_role = (
            self.db.query(UserRole)
            .filter(
                and_(
                    UserRole.user_id == user_id,
                    UserRole.role_id == role_id,
                    UserRole.tenant_id == tenant_id
                )
            )
            .first()
        )

        if user_role:
            self.db.delete(user_role)
            self.db.commit()
            return True

        return False

    async def grant_resource_permission(
        self,
        resource_type: str,
        resource_id: UUID,
        permission: str,
        tenant_id: UUID,
        granted_by: UUID,
        user_id: UUID | None = None,
        team_id: UUID | None = None,
        expires_at: str | None = None
    ) -> ResourcePermission:
        """Grant permission on a specific resource to a user or team."""
        if not user_id and not team_id:
            raise ValueError("Either user_id or team_id must be provided")

        if user_id and team_id:
            raise ValueError("Cannot grant to both user and team simultaneously")

        # Check if permission already exists
        existing = (
            self.db.query(ResourcePermission)
            .filter(
                and_(
                    ResourcePermission.resource_type == resource_type,
                    ResourcePermission.resource_id == resource_id,
                    ResourcePermission.user_id == user_id,
                    ResourcePermission.team_id == team_id,
                    ResourcePermission.permission == permission,
                    ResourcePermission.tenant_id == tenant_id
                )
            )
            .first()
        )

        if existing:
            return existing

        # Create new resource permission
        resource_permission = ResourcePermission(
            resource_type=resource_type,
            resource_id=resource_id,
            user_id=user_id,
            team_id=team_id,
            permission=permission,
            tenant_id=tenant_id,
            granted_by=granted_by,
            expires_at=expires_at
        )

        self.db.add(resource_permission)
        self.db.commit()
        return resource_permission

    async def revoke_resource_permission(
        self,
        resource_type: str,
        resource_id: UUID,
        permission: str,
        tenant_id: UUID,
        user_id: UUID | None = None,
        team_id: UUID | None = None
    ) -> bool:
        """Revoke permission on a specific resource from a user or team."""
        resource_permission = (
            self.db.query(ResourcePermission)
            .filter(
                and_(
                    ResourcePermission.resource_type == resource_type,
                    ResourcePermission.resource_id == resource_id,
                    ResourcePermission.user_id == user_id,
                    ResourcePermission.team_id == team_id,
                    ResourcePermission.permission == permission,
                    ResourcePermission.tenant_id == tenant_id
                )
            )
            .first()
        )

        if resource_permission:
            self.db.delete(resource_permission)
            self.db.commit()
            return True

        return False

    async def get_tenant_roles(self, tenant_id: UUID) -> list[dict]:
        """Get all roles available in a tenant."""
        roles = (
            self.db.query(Role)
            .filter(Role.tenant_id == tenant_id)
            .all()
        )

        result = []
        for role in roles:
            # Get permissions for this role
            permissions = (
                self.db.query(Permission.name)
                .join(RolePermission, Permission.id == RolePermission.permission_id)
                .filter(RolePermission.role_id == role.id)
                .all()
            )

            result.append({
                "id": str(role.id),
                "name": role.name,
                "description": role.description,
                "is_system": role.is_system,
                "permissions": [p[0] for p in permissions],
                "created_at": role.created_at.isoformat(),
                "updated_at": role.updated_at.isoformat()
            })

        return result

    async def get_user_resource_permissions(
        self,
        user_id: UUID,
        tenant_id: UUID,
        resource_type: str | None = None
    ) -> list[dict]:
        """Get resource-specific permissions for a user."""
        query = (
            self.db.query(ResourcePermission)
            .filter(
                and_(
                    ResourcePermission.tenant_id == tenant_id,
                    ResourcePermission.user_id == user_id
                )
            )
        )

        if resource_type:
            query = query.filter(ResourcePermission.resource_type == resource_type)

        permissions = query.all()

        return [
            {
                "id": str(perm.id),
                "resource_type": perm.resource_type,
                "resource_id": str(perm.resource_id),
                "permission": perm.permission,
                "granted_by": str(perm.granted_by),
                "granted_at": perm.granted_at.isoformat(),
                "expires_at": perm.expires_at.isoformat() if perm.expires_at else None
            }
            for perm in permissions
        ]

    async def create_custom_role(
        self,
        tenant_id: UUID,
        name: str,
        description: str,
        permissions: list[str],
        created_by: UUID
    ) -> Role:
        """Create a custom role with specified permissions."""
        # Check if role name already exists in tenant
        existing = (
            self.db.query(Role)
            .filter(
                and_(
                    Role.tenant_id == tenant_id,
                    Role.name == name
                )
            )
            .first()
        )

        if existing:
            raise ValueError(f"Role '{name}' already exists in this tenant")

        # Create the role
        role = Role(
            tenant_id=tenant_id,
            name=name,
            description=description,
            is_system=False
        )
        self.db.add(role)
        self.db.flush()

        # Add permissions
        for permission_name in permissions:
            await self._add_permission_to_role(role.id, permission_name)

        self.db.commit()
        return role
