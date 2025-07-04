"""
User repository implementation.
"""
from uuid import UUID

from sqlalchemy import select

from src.infrastructure.database.models.auth import User, UserDevice
from src.infrastructure.database.repositories.base import BaseRepository


class UserRepository(BaseRepository[User]):
    """Repository for User model."""

    async def get_by_email(self, email: str) -> User | None:
        """Get user by email address."""
        return await self.get_by(email=email)

    async def get_by_external_id(self, external_id: str) -> User | None:
        """Get user by external ID (Authentik ID)."""
        return await self.get_by(external_id=external_id)

    async def get_with_devices(self, user_id: UUID) -> User | None:
        """Get user with all their devices loaded."""
        return await self.get(user_id, load_relationships=['devices'])

    async def get_with_tenants(self, user_id: UUID) -> User | None:
        """Get user with all their tenant memberships loaded."""
        return await self.get(user_id, load_relationships=['tenants'])

    async def search_by_name_or_email(self, query: str, limit: int = 10) -> list[User]:
        """Search users by name or email."""
        search_term = f"%{query}%"
        stmt = select(User).where(
            (User.email.ilike(search_term)) |
            (User.full_name.ilike(search_term)) |
            (User.username.ilike(search_term))
        ).limit(limit)

        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def update_last_seen(self, user_id: UUID) -> None:
        """Update user's last seen timestamp."""
        from datetime import UTC, datetime
        await self.update(user_id, last_seen_at=datetime.now(UTC))


class UserDeviceRepository(BaseRepository[UserDevice]):
    """Repository for UserDevice model."""

    async def get_user_devices(self, user_id: UUID, only_active: bool = True) -> list[UserDevice]:
        """Get all devices for a user."""
        filters = {'user_id': user_id}
        if only_active:
            filters['is_active'] = True

        return await self.get_multi(filters=filters)

    async def get_by_device_id(self, device_id: str) -> UserDevice | None:
        """Get device by device ID."""
        return await self.get_by(device_id=device_id)

    async def get_by_credential_id(self, credential_id: str) -> UserDevice | None:
        """Get device by credential ID (for WebAuthn)."""
        return await self.get_by(credential_id=credential_id)

    async def mark_device_used(self, device_id: UUID) -> None:
        """Update device last used timestamp and increment use count."""
        from datetime import UTC, datetime
        device = await self.get(device_id)
        if device:
            await self.update(
                device_id,
                last_used_at=datetime.now(UTC),
                use_count=device.use_count + 1
            )

    async def deactivate_device(self, device_id: UUID) -> bool:
        """Deactivate a device."""
        result = await self.update(device_id, is_active=False)
        return result is not None
