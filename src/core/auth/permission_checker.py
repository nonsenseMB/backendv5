"""
Enhanced permission checker with performance optimizations and caching.
Implements advanced permission checking logic for task-132.
"""

from uuid import UUID

from sqlalchemy import and_, text
from sqlalchemy.orm import Session

from ...core.logging import get_logger
from ...infrastructure.database.models.tenant import TenantUser

logger = get_logger(__name__)


class EnhancedPermissionChecker:
    """
    Enhanced permission checker with performance optimizations.
    """

    def __init__(self, db: Session):
        self.db = db
        self._permission_cache: dict[str, bool] = {}
        self._role_cache: dict[UUID, set[str]] = {}

    async def check_permission(
        self,
        user_id: UUID,
        tenant_id: UUID,
        permission: str,
        resource_type: str | None = None,
        resource_id: UUID | None = None
    ) -> bool:
        """
        Enhanced permission checking with caching and optimization.
        
        Args:
            user_id: User ID
            tenant_id: Tenant ID
            permission: Permission string (e.g., 'conversation.create')
            resource_type: Optional resource type for resource-level checks
            resource_id: Optional resource ID for resource-level checks
            
        Returns:
            True if user has permission, False otherwise
        """
        # Create cache key
        cache_key = f"{user_id}:{tenant_id}:{permission}:{resource_type}:{resource_id}"

        # Check cache first
        if cache_key in self._permission_cache:
            logger.debug("Permission check cache hit", cache_key=cache_key)
            return self._permission_cache[cache_key]

        try:
            # First verify tenant access
            if not await self._verify_tenant_access(user_id, tenant_id):
                self._permission_cache[cache_key] = False
                return False

            # Check role-based permissions first (most common case)
            has_role_permission = await self._check_role_permission_optimized(
                user_id, tenant_id, permission
            )

            if has_role_permission:
                self._permission_cache[cache_key] = True
                return True

            # If resource provided, check resource-specific permissions
            if resource_type and resource_id:
                has_resource_permission = await self._check_resource_permission_optimized(
                    user_id, tenant_id, resource_type, resource_id, permission
                )

                self._permission_cache[cache_key] = has_resource_permission
                return has_resource_permission

            # No permission found
            self._permission_cache[cache_key] = False
            return False

        except Exception as e:
            logger.error(
                "Permission check failed",
                user_id=str(user_id),
                tenant_id=str(tenant_id),
                permission=permission,
                error=str(e)
            )
            # Fail secure - deny permission on error
            return False

    async def _verify_tenant_access(self, user_id: UUID, tenant_id: UUID) -> bool:
        """Verify user belongs to tenant."""
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
        return tenant_user is not None

    async def _check_role_permission_optimized(
        self, user_id: UUID, tenant_id: UUID, permission: str
    ) -> bool:
        """Optimized role-based permission checking with single query."""
        # Handle wildcard permissions (e.g., 'conversation.*' matches 'conversation.create')
        resource_wildcard = f"{permission.split('.')[0]}.*"

        # Single optimized query with joins
        query = text("""
            SELECT COUNT(*) > 0 as has_permission
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.id
            JOIN role_permissions rp ON r.id = rp.role_id
            JOIN permissions p ON rp.permission_id = p.id
            WHERE ur.user_id = :user_id
              AND ur.tenant_id = :tenant_id
              AND (p.name = :permission OR p.name = :wildcard)
        """)

        result = self.db.execute(
            query,
            {
                "user_id": str(user_id),
                "tenant_id": str(tenant_id),
                "permission": permission,
                "wildcard": resource_wildcard
            }
        ).fetchone()

        return bool(result and result[0])

    async def _check_resource_permission_optimized(
        self,
        user_id: UUID,
        tenant_id: UUID,
        resource_type: str,
        resource_id: UUID,
        permission: str
    ) -> bool:
        """Optimized resource-specific permission checking."""
        # Extract action from permission (e.g., 'create' from 'conversation.create')
        action = permission.split('.')[-1]

        # Check direct user permissions and team permissions in one query
        query = text("""
            SELECT COUNT(*) > 0 as has_permission
            FROM resource_permissions rp
            LEFT JOIN team_members tm ON rp.team_id = tm.team_id AND tm.user_id = :user_id
            WHERE rp.tenant_id = :tenant_id
              AND rp.resource_type = :resource_type
              AND rp.resource_id = :resource_id
              AND rp.permission = :action
              AND (rp.user_id = :user_id OR tm.user_id IS NOT NULL)
              AND (rp.expires_at IS NULL OR rp.expires_at > NOW())
        """)

        result = self.db.execute(
            query,
            {
                "user_id": str(user_id),
                "tenant_id": str(tenant_id),
                "resource_type": resource_type,
                "resource_id": str(resource_id),
                "action": action
            }
        ).fetchone()

        return bool(result and result[0])

    async def get_user_permissions_batch(
        self, user_id: UUID, tenant_id: UUID
    ) -> set[str]:
        """Get all permissions for a user with optimized batch query."""
        cache_key = f"user_perms:{user_id}:{tenant_id}"

        if cache_key in self._role_cache:
            return self._role_cache[cache_key]

        # Single query to get all role-based permissions
        query = text("""
            SELECT DISTINCT p.name
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.id
            JOIN role_permissions rp ON r.id = rp.role_id
            JOIN permissions p ON rp.permission_id = p.id
            WHERE ur.user_id = :user_id
              AND ur.tenant_id = :tenant_id
        """)

        result = self.db.execute(
            query,
            {"user_id": str(user_id), "tenant_id": str(tenant_id)}
        ).fetchall()

        permissions = {row[0] for row in result}
        self._role_cache[cache_key] = permissions

        return permissions

    async def check_permissions_batch(
        self,
        user_id: UUID,
        tenant_id: UUID,
        permissions: list[str]
    ) -> dict[str, bool]:
        """Check multiple permissions in a single operation."""
        # Get all user permissions once
        user_permissions = await self.get_user_permissions_batch(user_id, tenant_id)

        results = {}
        for permission in permissions:
            # Check exact match
            if permission in user_permissions:
                results[permission] = True
                continue

            # Check wildcard match
            resource = permission.split('.')[0]
            wildcard = f"{resource}.*"
            if wildcard in user_permissions:
                results[permission] = True
                continue

            results[permission] = False

        return results

    def clear_cache(self, user_id: UUID | None = None, tenant_id: UUID | None = None):
        """Clear permission cache for a user or entire cache."""
        if user_id and tenant_id:
            # Clear specific user cache
            keys_to_remove = [
                key for key in self._permission_cache.keys()
                if key.startswith(f"{user_id}:{tenant_id}:")
            ]
            for key in keys_to_remove:
                del self._permission_cache[key]

            # Clear role cache
            cache_key = f"user_perms:{user_id}:{tenant_id}"
            if cache_key in self._role_cache:
                del self._role_cache[cache_key]
        else:
            # Clear entire cache
            self._permission_cache.clear()
            self._role_cache.clear()

        logger.debug("Permission cache cleared", user_id=str(user_id) if user_id else None)

    async def validate_permission_hierarchy(
        self, permission: str, user_permissions: set[str]
    ) -> bool:
        """
        Validate permission using hierarchy rules.
        E.g., 'admin' permission grants access to everything.
        """
        # Check for super admin permissions
        if "admin" in user_permissions or "superuser" in user_permissions:
            return True

        # Check for tenant admin
        if "tenant.manage" in user_permissions:
            return True

        # Check for resource-level admin (e.g., 'conversation.*' covers all conversation permissions)
        if "." in permission:
            resource = permission.split(".")[0]
            if f"{resource}.*" in user_permissions:
                return True

        # Check exact permission
        return permission in user_permissions


# Convenience functions for common permission checks
async def has_admin_permission(db: Session, user_id: UUID, tenant_id: UUID) -> bool:
    """Check if user has admin permissions in tenant."""
    checker = EnhancedPermissionChecker(db)
    return await checker.check_permission(user_id, tenant_id, "tenant.manage")


async def has_resource_access(
    db: Session,
    user_id: UUID,
    tenant_id: UUID,
    resource_type: str,
    resource_id: UUID,
    action: str = "read"
) -> bool:
    """Check if user can access a specific resource."""
    checker = EnhancedPermissionChecker(db)
    permission = f"{resource_type}.{action}"
    return await checker.check_permission(
        user_id, tenant_id, permission, resource_type, resource_id
    )


async def get_accessible_resources(
    db: Session,
    user_id: UUID,
    tenant_id: UUID,
    resource_type: str
) -> list[UUID]:
    """Get list of resource IDs user can access."""
    # This would require a more complex query joining with the actual resource tables
    # For now, return empty list as placeholder
    return []
