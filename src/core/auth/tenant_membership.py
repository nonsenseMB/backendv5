"""
Enhanced tenant membership validation service.
Provides advanced validation, role hierarchy checks, and caching for tenant memberships.
Extends the basic TenantSwitcher functionality with enterprise features.
"""

from datetime import datetime, timedelta
from enum import Enum
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from ...infrastructure.database.models.auth import User
from ...infrastructure.database.models.permission import Permission, Role, UserRole
from ...infrastructure.database.models.tenant import Tenant, TenantUser
from ..logging import get_logger

logger = get_logger(__name__)


class TenantRole(str, Enum):
    """Standard tenant roles with hierarchy."""
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"
    GUEST = "guest"


class MembershipStatus(str, Enum):
    """Membership status types."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"
    SUSPENDED = "suspended"
    EXPIRED = "expired"


class TenantMembershipInfo:
    """Enhanced membership information with validation data."""

    def __init__(
        self,
        tenant_id: UUID,
        user_id: UUID,
        role: str,
        status: MembershipStatus,
        joined_at: datetime,
        last_accessed: datetime | None = None,
        permissions: list[str] | None = None,
        role_hierarchy_level: int = 0,
        invitation_details: dict[str, Any] | None = None
    ):
        self.tenant_id = tenant_id
        self.user_id = user_id
        self.role = role
        self.status = status
        self.joined_at = joined_at
        self.last_accessed = last_accessed
        self.permissions = permissions or []
        self.role_hierarchy_level = role_hierarchy_level
        self.invitation_details = invitation_details or {}

    def is_active(self) -> bool:
        """Check if membership is active."""
        return self.status == MembershipStatus.ACTIVE

    def has_permission(self, permission: str) -> bool:
        """Check if membership includes specific permission."""
        return permission in self.permissions

    def can_access_resource(self, resource_type: str, action: str) -> bool:
        """Check if membership allows access to resource with action."""
        required_permission = f"{resource_type}.{action}"
        return self.has_permission(required_permission)


class TenantMembershipValidator:
    """
    Advanced tenant membership validation service.
    Provides comprehensive validation, role hierarchy checks, and caching.
    """

    # Role hierarchy (higher number = more privileges)
    ROLE_HIERARCHY = {
        TenantRole.GUEST: 0,
        TenantRole.VIEWER: 1,
        TenantRole.MEMBER: 2,
        TenantRole.ADMIN: 3,
        TenantRole.OWNER: 4
    }

    def __init__(self, db: Session, enable_caching: bool = True):
        self.db = db
        self.enable_caching = enable_caching
        self._membership_cache: dict[str, TenantMembershipInfo] = {}
        self._cache_ttl = timedelta(minutes=15)  # Cache for 15 minutes
        self._cache_timestamps: dict[str, datetime] = {}

    async def validate_membership(
        self,
        user_id: UUID,
        tenant_id: UUID,
        require_active: bool = True
    ) -> TenantMembershipInfo | None:
        """
        Validate user membership in tenant with comprehensive checks.
        
        Args:
            user_id: The user's ID
            tenant_id: The tenant ID
            require_active: Whether to require active membership status
            
        Returns:
            TenantMembershipInfo if valid, None otherwise
        """
        cache_key = f"{user_id}:{tenant_id}"

        # Check cache first
        if self.enable_caching and self._is_cache_valid(cache_key):
            cached_membership = self._membership_cache.get(cache_key)
            if cached_membership and (not require_active or cached_membership.is_active()):
                logger.debug(
                    "Membership validation cache hit",
                    user_id=str(user_id),
                    tenant_id=str(tenant_id)
                )
                return cached_membership

        try:
            # Query membership with tenant and user validation
            membership_query = (
                self.db.query(TenantUser, Tenant, User)
                .join(Tenant, TenantUser.tenant_id == Tenant.id)
                .join(User, TenantUser.user_id == User.id)
                .filter(
                    TenantUser.user_id == user_id,
                    TenantUser.tenant_id == tenant_id,
                    Tenant.is_active == True,
                    User.is_active == True
                )
            )

            if require_active:
                membership_query = membership_query.filter(TenantUser.is_active == True)

            result = membership_query.first()

            if not result:
                logger.debug(
                    "Membership validation failed - no valid membership found",
                    user_id=str(user_id),
                    tenant_id=str(tenant_id),
                    require_active=require_active
                )
                return None

            tenant_user, tenant, user = result

            # Determine membership status
            status = self._determine_membership_status(tenant_user, tenant, user)

            # Get permissions for this membership
            permissions = await self._get_membership_permissions(user_id, tenant_id, tenant_user.role)

            # Get role hierarchy level
            role_level = self.ROLE_HIERARCHY.get(tenant_user.role, 0)

            # Create membership info
            membership_info = TenantMembershipInfo(
                tenant_id=tenant_id,
                user_id=user_id,
                role=tenant_user.role,
                status=status,
                joined_at=tenant_user.joined_at,
                last_accessed=getattr(tenant_user, 'last_accessed', None),
                permissions=permissions,
                role_hierarchy_level=role_level,
                invitation_details={
                    "invited_by": tenant_user.invited_by,
                    "invitation_accepted_at": tenant_user.invitation_accepted_at
                }
            )

            # Cache the result
            if self.enable_caching:
                self._cache_membership(cache_key, membership_info)

            logger.debug(
                "Membership validation successful",
                user_id=str(user_id),
                tenant_id=str(tenant_id),
                role=tenant_user.role,
                status=status.value
            )

            return membership_info

        except Exception as e:
            logger.error(
                "Membership validation error",
                user_id=str(user_id),
                tenant_id=str(tenant_id),
                error=str(e)
            )
            return None

    async def validate_role(
        self,
        user_id: UUID,
        tenant_id: UUID,
        required_role: str,
        allow_higher_roles: bool = True
    ) -> bool:
        """
        Check if user has required role in tenant with hierarchy support.
        
        Args:
            user_id: The user's ID
            tenant_id: The tenant ID
            required_role: The minimum required role
            allow_higher_roles: Whether higher roles satisfy the requirement
            
        Returns:
            True if user has required role or higher
        """
        try:
            membership = await self.validate_membership(user_id, tenant_id)
            if not membership:
                return False

            user_role_level = self.ROLE_HIERARCHY.get(membership.role, 0)
            required_role_level = self.ROLE_HIERARCHY.get(required_role, 0)

            if allow_higher_roles:
                has_role = user_role_level >= required_role_level
            else:
                has_role = user_role_level == required_role_level

            logger.debug(
                "Role validation result",
                user_id=str(user_id),
                tenant_id=str(tenant_id),
                user_role=membership.role,
                required_role=required_role,
                user_level=user_role_level,
                required_level=required_role_level,
                has_role=has_role
            )

            return has_role

        except Exception as e:
            logger.error(
                "Role validation error",
                user_id=str(user_id),
                tenant_id=str(tenant_id),
                required_role=required_role,
                error=str(e)
            )
            return False

    async def validate_permission(
        self,
        user_id: UUID,
        tenant_id: UUID,
        permission: str
    ) -> bool:
        """
        Check if user has specific permission in tenant.
        
        Args:
            user_id: The user's ID
            tenant_id: The tenant ID
            permission: The required permission
            
        Returns:
            True if user has the permission
        """
        try:
            membership = await self.validate_membership(user_id, tenant_id)
            if not membership:
                return False

            has_permission = membership.has_permission(permission)

            logger.debug(
                "Permission validation result",
                user_id=str(user_id),
                tenant_id=str(tenant_id),
                permission=permission,
                has_permission=has_permission
            )

            return has_permission

        except Exception as e:
            logger.error(
                "Permission validation error",
                user_id=str(user_id),
                tenant_id=str(tenant_id),
                permission=permission,
                error=str(e)
            )
            return False

    async def get_user_tenants_with_role(
        self,
        user_id: UUID,
        minimum_role: str
    ) -> list[TenantMembershipInfo]:
        """
        Get all tenants where user has at least the specified role.
        
        Args:
            user_id: The user's ID
            minimum_role: The minimum role level required
            
        Returns:
            List of TenantMembershipInfo objects
        """
        try:
            minimum_level = self.ROLE_HIERARCHY.get(minimum_role, 0)

            # Get all user memberships
            memberships = (
                self.db.query(TenantUser, Tenant)
                .join(Tenant, TenantUser.tenant_id == Tenant.id)
                .filter(
                    TenantUser.user_id == user_id,
                    TenantUser.is_active == True,
                    Tenant.is_active == True
                )
                .all()
            )

            result = []
            for tenant_user, tenant in memberships:
                user_role_level = self.ROLE_HIERARCHY.get(tenant_user.role, 0)

                if user_role_level >= minimum_level:
                    # Get permissions for this membership
                    permissions = await self._get_membership_permissions(
                        user_id, tenant.id, tenant_user.role
                    )

                    membership_info = TenantMembershipInfo(
                        tenant_id=tenant.id,
                        user_id=user_id,
                        role=tenant_user.role,
                        status=MembershipStatus.ACTIVE,
                        joined_at=tenant_user.joined_at,
                        last_accessed=getattr(tenant_user, 'last_accessed', None),
                        permissions=permissions,
                        role_hierarchy_level=user_role_level
                    )
                    result.append(membership_info)

            logger.debug(
                "User tenants with role retrieved",
                user_id=str(user_id),
                minimum_role=minimum_role,
                tenant_count=len(result)
            )

            return result

        except Exception as e:
            logger.error(
                "Error getting user tenants with role",
                user_id=str(user_id),
                minimum_role=minimum_role,
                error=str(e)
            )
            return []

    def invalidate_cache(self, user_id: UUID | None = None, tenant_id: UUID | None = None) -> None:
        """
        Invalidate membership cache entries.
        
        Args:
            user_id: If provided, invalidate all entries for this user
            tenant_id: If provided, invalidate all entries for this tenant
        """
        if not self.enable_caching:
            return

        if user_id and tenant_id:
            # Invalidate specific entry
            cache_key = f"{user_id}:{tenant_id}"
            self._membership_cache.pop(cache_key, None)
            self._cache_timestamps.pop(cache_key, None)
        elif user_id:
            # Invalidate all entries for user
            keys_to_remove = [key for key in self._membership_cache.keys() if key.startswith(f"{user_id}:")]
            for key in keys_to_remove:
                self._membership_cache.pop(key, None)
                self._cache_timestamps.pop(key, None)
        elif tenant_id:
            # Invalidate all entries for tenant
            keys_to_remove = [key for key in self._membership_cache.keys() if key.endswith(f":{tenant_id}")]
            for key in keys_to_remove:
                self._membership_cache.pop(key, None)
                self._cache_timestamps.pop(key, None)
        else:
            # Clear entire cache
            self._membership_cache.clear()
            self._cache_timestamps.clear()

        logger.debug(
            "Membership cache invalidated",
            user_id=str(user_id) if user_id else None,
            tenant_id=str(tenant_id) if tenant_id else None
        )

    def _determine_membership_status(
        self,
        tenant_user: TenantUser,
        tenant: Tenant,
        user: User
    ) -> MembershipStatus:
        """Determine the current status of a membership."""
        if not tenant_user.is_active:
            return MembershipStatus.INACTIVE
        if not tenant.is_active:
            return MembershipStatus.SUSPENDED
        if not user.is_active:
            return MembershipStatus.SUSPENDED

        # Check if invitation is still pending
        if tenant_user.invitation_accepted_at is None and tenant_user.invited_by:
            return MembershipStatus.PENDING

        return MembershipStatus.ACTIVE

    async def _get_membership_permissions(
        self,
        user_id: UUID,
        tenant_id: UUID,
        role: str
    ) -> list[str]:
        """Get all permissions for a user's membership in a tenant."""
        try:
            permissions = set()

            # Get role-based permissions from UserRole and Permission tables
            role_permissions = (
                self.db.query(Permission.name)
                .join(Role, Permission.roles)
                .join(UserRole, Role.id == UserRole.role_id)
                .filter(
                    UserRole.user_id == user_id,
                    UserRole.tenant_id == tenant_id,
                    UserRole.is_active == True
                )
                .distinct()
                .all()
            )

            permissions.update(p.name for p in role_permissions)

            # Get direct tenant permissions from TenantUser
            tenant_user = self.db.query(TenantUser).filter(
                TenantUser.user_id == user_id,
                TenantUser.tenant_id == tenant_id
            ).first()

            if tenant_user and tenant_user.permissions:
                permissions.update(tenant_user.permissions)

            # Add role-based default permissions
            default_permissions = self._get_default_role_permissions(role)
            permissions.update(default_permissions)

            return list(permissions)

        except Exception as e:
            logger.error(
                "Error getting membership permissions",
                user_id=str(user_id),
                tenant_id=str(tenant_id),
                role=role,
                error=str(e)
            )
            return []

    def _get_default_role_permissions(self, role: str) -> set[str]:
        """Get default permissions for a tenant role."""
        role_permissions = {
            TenantRole.OWNER: {
                "tenant.*", "user.*", "team.*", "agent.*",
                "conversation.*", "document.*", "billing.*"
            },
            TenantRole.ADMIN: {
                "tenant.read", "tenant.update", "user.*", "team.*",
                "agent.*", "conversation.*", "document.*"
            },
            TenantRole.MEMBER: {
                "tenant.read", "user.read", "team.read", "team.create",
                "agent.*", "conversation.*", "document.*"
            },
            TenantRole.VIEWER: {
                "tenant.read", "user.read", "team.read",
                "agent.read", "conversation.read", "document.read"
            },
            TenantRole.GUEST: {
                "tenant.read", "conversation.read"
            }
        }

        return role_permissions.get(role, set())

    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cache entry is still valid."""
        if cache_key not in self._cache_timestamps:
            return False

        cache_time = self._cache_timestamps[cache_key]
        return datetime.utcnow() - cache_time < self._cache_ttl

    def _cache_membership(self, cache_key: str, membership: TenantMembershipInfo) -> None:
        """Cache a membership validation result."""
        self._membership_cache[cache_key] = membership
        self._cache_timestamps[cache_key] = datetime.utcnow()

        # Clean old cache entries periodically
        if len(self._cache_timestamps) > 1000:  # Arbitrary limit
            self._clean_old_cache_entries()

    def _clean_old_cache_entries(self) -> None:
        """Remove expired cache entries."""
        current_time = datetime.utcnow()
        expired_keys = [
            key for key, timestamp in self._cache_timestamps.items()
            if current_time - timestamp > self._cache_ttl
        ]

        for key in expired_keys:
            self._membership_cache.pop(key, None)
            self._cache_timestamps.pop(key, None)

        logger.debug("Cache cleanup completed", removed_entries=len(expired_keys))
