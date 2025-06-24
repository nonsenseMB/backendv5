"""User service for authentication operations."""
from datetime import UTC, datetime
from uuid import UUID

from src.core.logging import get_logger
from src.infrastructure.database.models.auth import User
from src.infrastructure.database.repositories.user import UserRepository
from src.infrastructure.database.unit_of_work import UnitOfWork

logger = get_logger(__name__)


class UserService:
    """Service for user management operations."""

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    async def get_or_create_by_external_id(
        self,
        external_id: str,
        email: str,
        name: str | None = None,
        tenant_id: UUID | None = None,
        attributes: dict | None = None,
    ) -> User:
        """Get or create a user by external ID (Authentik ID)."""
        async with self.uow:
            user_repo = self.uow.users

            # Try to find existing user
            user = await user_repo.get_by_external_id(external_id)

            if user:
                # Update user information if changed
                update_fields = {}

                if user.email != email:
                    update_fields["email"] = email

                if name and user.full_name != name:
                    update_fields["full_name"] = name

                if not user.is_verified and attributes and attributes.get("email_verified"):
                    update_fields["is_verified"] = True

                update_fields["last_seen_at"] = datetime.now(UTC)

                if update_fields:
                    user = await user_repo.update(user.id, **update_fields)
                    await self.uow.commit()

                    logger.info(
                        "Updated existing user",
                        user_id=str(user.id),
                        external_id=external_id,
                        email=email,
                        updated_fields=list(update_fields.keys()),
                    )
            else:
                # Create new user
                user_data = {
                    "external_id": external_id,
                    "email": email,
                    "full_name": name,
                    "is_verified": attributes.get("email_verified", False) if attributes else False,
                    "is_active": True,
                    "last_seen_at": datetime.now(UTC),
                    "extra_data": attributes or {},
                }

                # Extract username from attributes or email
                if attributes and attributes.get("preferred_username"):
                    user_data["username"] = attributes["preferred_username"]
                else:
                    user_data["username"] = email.split("@")[0]

                user = await user_repo.create(**user_data)
                await self.uow.commit()

                logger.info(
                    "Created new user",
                    user_id=str(user.id),
                    external_id=external_id,
                    email=email,
                )

                # If tenant_id provided, add user to tenant
                # This would require TenantUserRepository implementation
                # if tenant_id:
                #     await self._add_user_to_tenant(user.id, tenant_id)

            return user

    async def get_by_id(self, user_id: UUID) -> User | None:
        """Get user by ID."""
        async with self.uow:
            user_repo = self.uow.users
            return await user_repo.get(user_id)

    async def get_by_email(self, email: str) -> User | None:
        """Get user by email."""
        async with self.uow:
            user_repo = self.uow.users
            return await user_repo.get_by_email(email)

    async def update_last_seen(self, user_id: UUID) -> None:
        """Update user's last seen timestamp."""
        async with self.uow:
            user_repo = self.uow.users
            await user_repo.update_last_seen(user_id)
            await self.uow.commit()
