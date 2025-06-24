"""
Tenant repository implementation.
"""
from datetime import datetime
from uuid import UUID

from sqlalchemy import and_, select

from src.infrastructure.database.models.tenant import Tenant, TenantUser
from src.infrastructure.database.repositories.base import BaseRepository, TenantAwareRepository


class TenantRepository(BaseRepository[Tenant]):
    """Repository for Tenant model."""

    async def get_by_slug(self, slug: str) -> Tenant | None:
        """Get tenant by slug."""
        return await self.get_by(slug=slug)

    async def get_by_domain(self, domain: str) -> Tenant | None:
        """Get tenant by domain."""
        return await self.get_by(domain=domain)

    async def get_active_tenants(self, skip: int = 0, limit: int = 100) -> list[Tenant]:
        """Get all active tenants."""
        return await self.get_multi(
            skip=skip,
            limit=limit,
            filters={'is_active': True}
        )

    async def search_by_name(self, query: str, limit: int = 10) -> list[Tenant]:
        """Search tenants by name."""
        search_term = f"%{query}%"
        stmt = select(Tenant).where(
            Tenant.name.ilike(search_term) &
            (Tenant.is_active == True)
        ).limit(limit)

        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def is_slug_available(self, slug: str) -> bool:
        """Check if a slug is available."""
        return not await self.exists(slug=slug)

    async def activate_tenant(self, tenant_id: UUID) -> Tenant | None:
        """Activate a tenant."""
        return await self.update(
            tenant_id,
            is_active=True,
            activation_date=datetime.utcnow()
        )

    async def deactivate_tenant(self, tenant_id: UUID) -> Tenant | None:
        """Deactivate a tenant."""
        return await self.update(tenant_id, is_active=False)

    async def update_usage_limits(
        self,
        tenant_id: UUID,
        max_users: int = None,
        max_teams: int = None,
        max_agents: int = None,
        max_monthly_tokens: int = None,
        max_storage_gb: int = None
    ) -> Tenant | None:
        """Update tenant usage limits."""
        update_data = {}
        if max_users is not None:
            update_data['max_users'] = max_users
        if max_teams is not None:
            update_data['max_teams'] = max_teams
        if max_agents is not None:
            update_data['max_agents'] = max_agents
        if max_monthly_tokens is not None:
            update_data['max_monthly_tokens'] = max_monthly_tokens
        if max_storage_gb is not None:
            update_data['max_storage_gb'] = max_storage_gb

        if update_data:
            return await self.update(tenant_id, **update_data)
        return await self.get(tenant_id)


class TenantUserRepository(TenantAwareRepository[TenantUser]):
    """Repository for TenantUser model."""

    async def get_user_tenants(self, user_id: UUID) -> list[TenantUser]:
        """Get all tenant memberships for a user."""
        stmt = select(TenantUser).where(
            TenantUser.user_id == user_id
        ).options(
            selectinload(TenantUser.tenant)
        )

        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_tenant_users(
        self,
        skip: int = 0,
        limit: int = 100,
        role: str = None,
        is_active: bool = True
    ) -> list[TenantUser]:
        """Get all users in the current tenant."""
        filters = {}
        if role:
            filters['role'] = role
        if is_active is not None:
            filters['is_active'] = is_active

        return await self.get_multi(
            skip=skip,
            limit=limit,
            filters=filters,
            load_relationships=['user']
        )

    async def get_membership(self, user_id: UUID) -> TenantUser | None:
        """Get a specific user's membership in the current tenant."""
        stmt = select(TenantUser).where(
            and_(
                TenantUser.tenant_id == self.tenant_id,
                TenantUser.user_id == user_id
            )
        )

        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def add_user_to_tenant(
        self,
        user_id: UUID,
        role: str = 'member',
        permissions: dict = None
    ) -> TenantUser:
        """Add a user to the current tenant."""
        return await self.create(
            user_id=user_id,
            role=role,
            permissions=permissions or {},
            is_active=True,
            joined_at=datetime.utcnow()
        )

    async def update_user_role(
        self,
        user_id: UUID,
        role: str,
        permissions: dict = None
    ) -> TenantUser | None:
        """Update a user's role in the current tenant."""
        membership = await self.get_membership(user_id)
        if not membership:
            return None

        update_data = {'role': role}
        if permissions is not None:
            update_data['permissions'] = permissions

        return await self.update(membership.id, **update_data)

    async def remove_user_from_tenant(self, user_id: UUID) -> bool:
        """Remove a user from the current tenant."""
        membership = await self.get_membership(user_id)
        if not membership:
            return False

        return await self.delete(membership.id)

    async def deactivate_user_in_tenant(self, user_id: UUID) -> TenantUser | None:
        """Deactivate a user in the current tenant."""
        membership = await self.get_membership(user_id)
        if not membership:
            return None

        return await self.update(membership.id, is_active=False)
