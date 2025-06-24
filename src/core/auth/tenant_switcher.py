"""
Tenant switching service implementation.
Handles secure tenant switching with proper validation and JWT management.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from ...infrastructure.database.models.auth import User
from ...infrastructure.database.models.permission import Permission, Role, UserRole
from ...infrastructure.database.models.tenant import Tenant, TenantUser
from ..logging import get_logger
from ..logging.audit import AuditEventType, AuditSeverity, log_audit_event
from .jwt_manager import JWTManager

logger = get_logger(__name__)


class TenantSwitchError(Exception):
    """Base exception for tenant switching errors."""
    pass


class TenantAccessDeniedError(TenantSwitchError):
    """User does not have access to the target tenant."""
    pass


class TenantNotFoundError(TenantSwitchError):
    """Target tenant does not exist."""
    pass


class UserTenantMembership:
    """Represents a user's membership in a tenant."""

    def __init__(
        self,
        tenant_id: UUID,
        tenant_name: str,
        tenant_slug: str,
        user_role: str,
        is_active: bool,
        joined_at: datetime,
        last_accessed: datetime | None = None,
        permissions: list[str] | None = None
    ):
        self.tenant_id = tenant_id
        self.tenant_name = tenant_name
        self.tenant_slug = tenant_slug
        self.user_role = user_role
        self.is_active = is_active
        self.joined_at = joined_at
        self.last_accessed = last_accessed
        self.permissions = permissions or []


class TenantSwitcher:
    """
    Service for handling tenant switching operations.
    Manages validation, permission checking, and secure token generation.
    """

    def __init__(self, db: Session, jwt_manager: JWTManager | None = None):
        self.db = db
        self.jwt_manager = jwt_manager or JWTManager()

    async def get_user_tenants(self, user_id: UUID) -> list[UserTenantMembership]:
        """
        Get all tenants that a user belongs to with their roles and permissions.
        
        Args:
            user_id: The user's ID
            
        Returns:
            List of UserTenantMembership objects
        """
        try:
            # Query user's tenant memberships
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
                # Get user permissions in this tenant
                permissions = await self._get_user_tenant_permissions(user_id, tenant.id)

                membership = UserTenantMembership(
                    tenant_id=tenant.id,
                    tenant_name=tenant.name,
                    tenant_slug=tenant.slug,
                    user_role=tenant_user.role,
                    is_active=tenant_user.is_active,
                    joined_at=tenant_user.joined_at,
                    last_accessed=getattr(tenant_user, 'last_accessed', None),
                    permissions=permissions
                )
                result.append(membership)

            logger.debug(
                "Retrieved user tenants",
                user_id=str(user_id),
                tenant_count=len(result)
            )

            return result

        except Exception as e:
            logger.error(
                "Failed to get user tenants",
                user_id=str(user_id),
                error=str(e)
            )
            raise

    async def verify_tenant_membership(
        self,
        user_id: UUID,
        tenant_id: UUID
    ) -> UserTenantMembership | None:
        """
        Verify that a user has active membership in a tenant.
        
        Args:
            user_id: The user's ID
            tenant_id: The target tenant ID
            
        Returns:
            UserTenantMembership if valid, None otherwise
        """
        try:
            # Check if tenant exists and is active
            tenant = self.db.query(Tenant).filter(
                Tenant.id == tenant_id,
                Tenant.is_active == True
            ).first()

            if not tenant:
                logger.warning(
                    "Tenant not found or inactive",
                    tenant_id=str(tenant_id),
                    user_id=str(user_id)
                )
                return None

            # Check user membership
            membership = self.db.query(TenantUser).filter(
                TenantUser.user_id == user_id,
                TenantUser.tenant_id == tenant_id,
                TenantUser.is_active == True
            ).first()

            if not membership:
                logger.warning(
                    "User not a member of tenant",
                    user_id=str(user_id),
                    tenant_id=str(tenant_id)
                )
                return None

            # Get permissions
            permissions = await self._get_user_tenant_permissions(user_id, tenant_id)

            return UserTenantMembership(
                tenant_id=tenant.id,
                tenant_name=tenant.name,
                tenant_slug=tenant.slug,
                user_role=membership.role,
                is_active=membership.is_active,
                joined_at=membership.joined_at,
                last_accessed=getattr(membership, 'last_accessed', None),
                permissions=permissions
            )

        except Exception as e:
            logger.error(
                "Failed to verify tenant membership",
                user_id=str(user_id),
                tenant_id=str(tenant_id),
                error=str(e)
            )
            return None

    async def switch_tenant(
        self,
        user_id: UUID,
        target_tenant_id: UUID,
        current_session_id: str | None = None
    ) -> dict[str, Any]:
        """
        Switch user to a different tenant with new JWT tokens.
        
        Args:
            user_id: The user's ID
            target_tenant_id: The target tenant ID
            current_session_id: Current session ID for audit trail
            
        Returns:
            Dictionary with new tokens and tenant info
            
        Raises:
            TenantNotFoundError: If tenant doesn't exist
            TenantAccessDeniedError: If user doesn't have access
        """
        try:
            # Verify membership
            membership = await self.verify_tenant_membership(user_id, target_tenant_id)
            if not membership:
                raise TenantAccessDeniedError(
                    f"User {user_id} does not have access to tenant {target_tenant_id}"
                )

            # Get user details
            user = self.db.query(User).filter(User.id == user_id).first()
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )

            # Create new JWT tokens with target tenant context
            access_token = self.jwt_manager.create_access_token(
                user_id=str(user_id),
                tenant_id=str(target_tenant_id),
                session_id=current_session_id or "",
                scopes=membership.permissions,
                additional_claims={
                    "email": user.email,
                    "role": membership.user_role
                }
            )

            refresh_token = self.jwt_manager.create_refresh_token(
                user_id=str(user_id),
                tenant_id=str(target_tenant_id),
                session_id=current_session_id or ""
            )

            # Update last accessed timestamp
            await self._update_tenant_last_accessed(user_id, target_tenant_id)

            # Log the tenant switch event
            await log_audit_event(
                event_type=AuditEventType.TENANT_SWITCHED,
                severity=AuditSeverity.MEDIUM,
                details={
                    "user_id": str(user_id),
                    "target_tenant_id": str(target_tenant_id),
                    "tenant_name": membership.tenant_name,
                    "user_role": membership.user_role,
                    "session_id": current_session_id,
                    "timestamp": datetime.utcnow().isoformat()
                }
            )

            logger.info(
                "Tenant switched successfully",
                user_id=str(user_id),
                target_tenant_id=str(target_tenant_id),
                tenant_name=membership.tenant_name,
                user_role=membership.user_role
            )

            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "tenant": {
                    "tenant_id": membership.tenant_id,
                    "tenant_name": membership.tenant_name,
                    "tenant_slug": membership.tenant_slug,
                    "user_role": membership.user_role,
                    "is_active": membership.is_active,
                    "joined_at": membership.joined_at,
                    "last_accessed": datetime.utcnow(),
                    "permissions": membership.permissions
                }
            }

        except TenantSwitchError:
            raise
        except Exception as e:
            logger.error(
                "Failed to switch tenant",
                user_id=str(user_id),
                target_tenant_id=str(target_tenant_id),
                error=str(e)
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Tenant switch failed"
            )

    async def get_current_tenant_info(
        self,
        user_id: UUID,
        tenant_id: UUID
    ) -> UserTenantMembership | None:
        """
        Get current tenant information for a user.
        
        Args:
            user_id: The user's ID
            tenant_id: The current tenant ID
            
        Returns:
            UserTenantMembership if valid, None otherwise
        """
        return await self.verify_tenant_membership(user_id, tenant_id)

    async def _get_user_tenant_permissions(
        self,
        user_id: UUID,
        tenant_id: UUID
    ) -> list[str]:
        """
        Get all permissions for a user in a specific tenant.
        
        Args:
            user_id: The user's ID
            tenant_id: The tenant ID
            
        Returns:
            List of permission names
        """
        try:
            # Get role-based permissions
            permissions = (
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

            permission_names = [p.name for p in permissions]

            # Get direct tenant permissions from TenantUser
            tenant_user = self.db.query(TenantUser).filter(
                TenantUser.user_id == user_id,
                TenantUser.tenant_id == tenant_id
            ).first()

            if tenant_user and tenant_user.permissions:
                permission_names.extend(tenant_user.permissions)

            # Remove duplicates and return
            return list(set(permission_names))

        except Exception as e:
            logger.error(
                "Failed to get user tenant permissions",
                user_id=str(user_id),
                tenant_id=str(tenant_id),
                error=str(e)
            )
            return []

    async def _update_tenant_last_accessed(
        self,
        user_id: UUID,
        tenant_id: UUID
    ) -> None:
        """
        Update the last accessed timestamp for a user-tenant relationship.
        
        Args:
            user_id: The user's ID
            tenant_id: The tenant ID
        """
        try:
            tenant_user = self.db.query(TenantUser).filter(
                TenantUser.user_id == user_id,
                TenantUser.tenant_id == tenant_id
            ).first()

            if tenant_user:
                # Add last_accessed field if it doesn't exist
                if not hasattr(tenant_user, 'last_accessed'):
                    # This would require a database migration to add the column
                    # For now, we'll skip this update
                    logger.debug(
                        "last_accessed field not available for tenant user",
                        user_id=str(user_id),
                        tenant_id=str(tenant_id)
                    )
                    return

                tenant_user.last_accessed = datetime.utcnow()
                self.db.commit()

                logger.debug(
                    "Updated tenant last accessed",
                    user_id=str(user_id),
                    tenant_id=str(tenant_id)
                )

        except Exception as e:
            logger.warning(
                "Failed to update tenant last accessed",
                user_id=str(user_id),
                tenant_id=str(tenant_id),
                error=str(e)
            )
            # Don't raise exception as this is not critical
