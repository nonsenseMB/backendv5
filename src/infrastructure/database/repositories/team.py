"""
Team repository implementation.
"""
from datetime import datetime
from uuid import UUID

from sqlalchemy import and_, func, or_, select

from infrastructure.database.models.team import Team, TeamMember
from infrastructure.database.repositories.base import BaseRepository, TenantAwareRepository


class TeamRepository(TenantAwareRepository[Team]):
    """Repository for Team model."""

    async def get_by_slug(self, slug: str) -> Team | None:
        """Get team by slug within the tenant."""
        stmt = select(Team).where(
            and_(
                Team.tenant_id == self.tenant_id,
                Team.slug == slug
            )
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_user_teams(
        self,
        user_id: UUID,
        only_active: bool = True
    ) -> list[Team]:
        """Get all teams a user is a member of."""
        stmt = select(Team).join(TeamMember).where(
            and_(
                Team.tenant_id == self.tenant_id,
                TeamMember.user_id == user_id,
                TeamMember.is_active == True
            )
        )

        if only_active:
            stmt = stmt.where(Team.is_active == True)

        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_teams_created_by_user(self, user_id: UUID) -> list[Team]:
        """Get all teams created by a specific user."""
        return await self.get_multi(
            filters={'created_by': user_id},
            order_by='-created_at'
        )

    async def search_teams(
        self,
        query: str,
        include_inactive: bool = False,
        limit: int = 20
    ) -> list[Team]:
        """Search teams by name or description."""
        search_term = f"%{query}%"
        stmt = select(Team).where(
            and_(
                Team.tenant_id == self.tenant_id,
                or_(
                    Team.name.ilike(search_term),
                    Team.description.ilike(search_term)
                )
            )
        )

        if not include_inactive:
            stmt = stmt.where(Team.is_active == True)

        stmt = stmt.limit(limit)

        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def create_team(
        self,
        name: str,
        slug: str,
        created_by: UUID,
        description: str = None,
        avatar_url: str = None,
        settings: dict = None
    ) -> Team:
        """Create a new team."""
        return await self.create(
            name=name,
            slug=slug,
            created_by=created_by,
            description=description,
            avatar_url=avatar_url,
            settings=settings or {
                "notifications": True,
                "auto_share_conversations": False,
                "default_share_permission": "read"
            },
            is_active=True,
            member_count=1  # Creator is automatically a member
        )

    async def update_member_count(self, team_id: UUID) -> Team | None:
        """Update the member count for a team."""
        # Count active members
        stmt = select(func.count()).where(
            and_(
                TeamMember.team_id == team_id,
                TeamMember.is_active == True
            )
        )
        result = await self.session.execute(stmt)
        count = result.scalar()

        return await self.update(team_id, member_count=count)

    async def update_settings(
        self,
        team_id: UUID,
        settings: dict
    ) -> Team | None:
        """Update team settings."""
        team = await self.get(team_id)
        if not team:
            return None

        # Merge with existing settings
        current_settings = team.settings or {}
        current_settings.update(settings)

        return await self.update(team_id, settings=current_settings)

    async def assign_team_agent(
        self,
        team_id: UUID,
        agent_id: UUID
    ) -> Team | None:
        """Assign an agent to a team."""
        return await self.update(team_id, team_agent_id=agent_id)

    async def generate_channel_id(self, team_id: UUID) -> Team | None:
        """Generate a unique WebSocket channel ID for the team."""
        import secrets
        channel_id = f"team-{team_id}-{secrets.token_urlsafe(16)}"
        return await self.update(team_id, ws_channel_id=channel_id)

    async def is_slug_available(self, slug: str) -> bool:
        """Check if a team slug is available within the tenant."""
        existing = await self.get_by_slug(slug)
        return existing is None


class TeamMemberRepository(BaseRepository[TeamMember]):
    """Repository for TeamMember model."""

    async def get_team_members(
        self,
        team_id: UUID,
        only_active: bool = True,
        skip: int = 0,
        limit: int = 100
    ) -> list[TeamMember]:
        """Get all members of a team."""
        filters = {'team_id': team_id}
        if only_active:
            filters['is_active'] = True

        return await self.get_multi(
            skip=skip,
            limit=limit,
            filters=filters,
            order_by='joined_at',
            load_relationships=['user']
        )

    async def get_member(
        self,
        team_id: UUID,
        user_id: UUID
    ) -> TeamMember | None:
        """Get a specific team member."""
        return await self.get_by(
            team_id=team_id,
            user_id=user_id
        )

    async def get_user_memberships(
        self,
        user_id: UUID,
        only_active: bool = True
    ) -> list[TeamMember]:
        """Get all team memberships for a user."""
        filters = {'user_id': user_id}
        if only_active:
            filters['is_active'] = True

        return await self.get_multi(
            filters=filters,
            order_by='-joined_at',
            load_relationships=['team']
        )

    async def add_member(
        self,
        team_id: UUID,
        user_id: UUID,
        role: str = 'member',
        invited_by: UUID = None,
        permissions: list[str] = None
    ) -> TeamMember:
        """Add a user to a team."""
        # Check if already a member
        existing = await self.get_member(team_id, user_id)
        if existing:
            if not existing.is_active:
                # Reactivate membership
                return await self.update(
                    existing.id,
                    is_active=True,
                    role=role,
                    permissions=permissions or [],
                    joined_at=datetime.utcnow()
                )
            return existing

        return await self.create(
            team_id=team_id,
            user_id=user_id,
            role=role,
            invited_by=invited_by,
            permissions=permissions or [],
            is_active=True,
            joined_at=datetime.utcnow()
        )

    async def update_member_role(
        self,
        team_id: UUID,
        user_id: UUID,
        role: str,
        permissions: list[str] = None
    ) -> TeamMember | None:
        """Update a member's role and permissions."""
        member = await self.get_member(team_id, user_id)
        if not member:
            return None

        update_data = {'role': role}
        if permissions is not None:
            update_data['permissions'] = permissions

        return await self.update(member.id, **update_data)

    async def remove_member(
        self,
        team_id: UUID,
        user_id: UUID
    ) -> bool:
        """Remove a member from a team (soft delete)."""
        member = await self.get_member(team_id, user_id)
        if not member:
            return False

        result = await self.update(member.id, is_active=False)
        return result is not None

    async def get_team_owners(self, team_id: UUID) -> list[TeamMember]:
        """Get all owners of a team."""
        return await self.get_multi(
            filters={
                'team_id': team_id,
                'role': 'owner',
                'is_active': True
            },
            load_relationships=['user']
        )

    async def get_team_admins(self, team_id: UUID) -> list[TeamMember]:
        """Get all admins (owners + admins) of a team."""
        return await self.get_multi(
            filters={
                'team_id': team_id,
                'is_active': True
            },
            load_relationships=['user']
        )

    async def has_permission(
        self,
        team_id: UUID,
        user_id: UUID,
        permission: str
    ) -> bool:
        """Check if a user has a specific permission in a team."""
        member = await self.get_member(team_id, user_id)
        if not member or not member.is_active:
            return False

        # Owners have all permissions
        if member.role == 'owner':
            return True

        # Admins have most permissions
        if member.role == 'admin' and permission != 'delete_team':
            return True

        # Check specific permissions
        return permission in (member.permissions or [])

    async def transfer_ownership(
        self,
        team_id: UUID,
        from_user_id: UUID,
        to_user_id: UUID
    ) -> bool:
        """Transfer team ownership from one user to another."""
        # Verify current owner
        current_owner = await self.get_member(team_id, from_user_id)
        if not current_owner or current_owner.role != 'owner':
            return False

        # Update new owner
        new_owner = await self.get_member(team_id, to_user_id)
        if not new_owner:
            return False

        # Make the transfer
        await self.update(new_owner.id, role='owner')
        await self.update(current_owner.id, role='admin')

        return True
