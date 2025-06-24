"""
Team service for managing teams and memberships.
"""
from typing import Optional
from uuid import UUID

from src.core.auth.exceptions import PermissionDeniedError
from src.core.logging import get_logger
from src.core.logging.audit import AuditEventType, AuditSeverity, log_audit_event
from src.infrastructure.database.models.team import Team, TeamMember
from src.infrastructure.database.unit_of_work import UnitOfWork

logger = get_logger(__name__)


class TeamError(Exception):
    """Base exception for team operations."""
    pass


class TeamLimitExceededError(TeamError):
    """Raised when tenant team limit is exceeded."""
    pass


class TeamNotFoundError(TeamError):
    """Raised when team is not found."""
    pass


class AlreadyMemberError(TeamError):
    """Raised when user is already a team member."""
    pass


class LastAdminError(TeamError):
    """Raised when trying to remove the last admin."""
    pass


class TeamService:
    """Service for managing teams and team memberships."""

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    async def create_team(
        self,
        name: str,
        slug: str,
        created_by: UUID,
        description: Optional[str] = None,
        avatar_url: Optional[str] = None,
        settings: Optional[dict] = None
    ) -> Team:
        """
        Create a new team.
        
        Args:
            name: Team name
            slug: Team slug (unique within tenant)
            created_by: User ID creating the team
            description: Optional team description
            avatar_url: Optional avatar URL
            settings: Optional team settings
            
        Returns:
            Created team
            
        Raises:
            TeamLimitExceededError: If tenant team limit exceeded
            ValueError: If slug is already taken
        """
        try:
            # Check tenant team limit
            tenant_id = self.uow.tenant_id
            if not tenant_id:
                raise ValueError("No tenant context")
            tenant = await self.uow.tenants.get(tenant_id)
            if not tenant:
                raise ValueError("Invalid tenant")

            team_count = await self.uow.teams.count(filters={'tenant_id': self.uow.tenant_id})
            if team_count >= tenant.max_teams:
                logger.warning(
                    "Team limit exceeded",
                    tenant_id=self.uow.tenant_id,
                    limit=tenant.max_teams,
                    current=team_count
                )
                raise TeamLimitExceededError(f"Team limit of {tenant.max_teams} exceeded")

            # Check slug availability
            if not await self.uow.teams.is_slug_available(slug):
                raise ValueError(f"Team slug '{slug}' is already taken")

            # Create team
            team = await self.uow.teams.create_team(
                name=name,
                slug=slug,
                created_by=created_by,
                description=description,
                avatar_url=avatar_url,
                settings=settings
            )

            # Add creator as owner
            await self.uow.team_members.add_member(
                team_id=team.id,
                user_id=created_by,
                role='owner',
                invited_by=None,
                permissions=[]
            )

            # Log audit event
            log_audit_event(
                event_type=AuditEventType.TEAM_CREATED,
                severity=AuditSeverity.MEDIUM,
                details={
                    'team_id': str(team.id),
                    'team_name': name,
                    'created_by': str(created_by)
                }
            )

            await self.uow.commit()

            logger.info(
                "Team created",
                team_id=team.id,
                name=name,
                created_by=created_by
            )

            return team
            
        except (TeamLimitExceededError, ValueError):
            await self.uow.rollback()
            raise
        except Exception as e:
            await self.uow.rollback()
            logger.error(
                "Failed to create team",
                name=name,
                slug=slug,
                created_by=created_by,
                error=str(e)
            )
            raise TeamError(f"Failed to create team: {str(e)}")

    async def add_member(
        self,
        team_id: UUID,
        user_id: UUID,
        role: str = 'member',
        invited_by: Optional[UUID] = None,
        permissions: Optional[list[str]] = None
    ) -> TeamMember:
        """
        Add a member to a team.
        
        Args:
            team_id: Team ID
            user_id: User ID to add
            role: Member role (owner, admin, member, viewer)
            invited_by: User ID who invited
            permissions: Optional additional permissions
            
        Returns:
            Team member object
            
        Raises:
            TeamNotFoundError: If team not found
            PermissionDeniedError: If user cannot add members
            AlreadyMemberError: If user is already a member
        """
        # Check if team exists
        team = await self.uow.teams.get(team_id)
        if not team:
            raise TeamNotFoundError(f"Team {team_id} not found")

        # Check if inviter has permission
        if invited_by:
            if not await self.is_team_admin(team_id, invited_by):
                raise PermissionDeniedError("Only admins can add members")

        # Check if user belongs to same tenant
        user = await self.uow.users.get(user_id)
        if not user:
            raise ValueError("User not found")

        user_tenant = await self.uow.tenant_users.get_by(
            user_id=user_id,
            tenant_id=self.uow.tenant_id
        )
        if not user_tenant:
            raise ValueError("User does not belong to this tenant")

        # Check if already a member
        existing = await self.uow.team_members.get_member(team_id, user_id)
        if existing and existing.is_active:
            raise AlreadyMemberError(f"User {user_id} is already a member")

        # Add member
        member = await self.uow.team_members.add_member(
            team_id=team_id,
            user_id=user_id,
            role=role,
            invited_by=invited_by,
            permissions=permissions
        )

        # Update member count
        await self.uow.teams.update_member_count(team_id)

        # Log audit event
        log_audit_event(
            event_type=AuditEventType.TEAM_MEMBER_ADDED,
            severity=AuditSeverity.LOW,
            details={
                'team_id': str(team_id),
                'user_id': str(user_id),
                'role': role,
                'invited_by': str(invited_by) if invited_by else None
            }
        )

        await self.uow.commit()

        logger.info(
            "Team member added",
            team_id=team_id,
            user_id=user_id,
            role=role
        )

        return member

    async def remove_member(
        self,
        team_id: UUID,
        user_id: UUID,
        removed_by: UUID
    ) -> bool:
        """
        Remove a member from a team.
        
        Args:
            team_id: Team ID
            user_id: User ID to remove
            removed_by: User ID performing removal
            
        Returns:
            True if removed successfully
            
        Raises:
            TeamNotFoundError: If team not found
            PermissionDeniedError: If user cannot remove members
            LastAdminError: If trying to remove last admin
        """
        # Check if team exists
        team = await self.uow.teams.get(team_id)
        if not team:
            raise TeamNotFoundError(f"Team {team_id} not found")

        # Check permissions
        if not await self.is_team_admin(team_id, removed_by):
            # Users can remove themselves
            if removed_by != user_id:
                raise PermissionDeniedError("Only admins can remove members")

        # Check if last admin/owner
        member = await self.uow.team_members.get_member(team_id, user_id)
        if member and member.role in ['owner', 'admin']:
            admins = await self.uow.team_members.get_team_admins(team_id)
            active_admins = [m for m in admins if m.is_active and m.role in ['owner', 'admin']]
            if len(active_admins) <= 1:
                raise LastAdminError("Cannot remove the last admin")

        # Remove member
        success = await self.uow.team_members.remove_member(team_id, user_id)

        if success:
            # Update member count
            await self.uow.teams.update_member_count(team_id)

            # Log audit event
            log_audit_event(
                event_type=AuditEventType.TEAM_MEMBER_REMOVED,
                severity=AuditSeverity.LOW,
                details={
                    'team_id': str(team_id),
                    'user_id': str(user_id),
                    'removed_by': str(removed_by)
                }
            )

            await self.uow.commit()

            logger.info(
                "Team member removed",
                team_id=team_id,
                user_id=user_id,
                removed_by=removed_by
            )

        return success

    async def update_team(
        self,
        team_id: UUID,
        updated_by: UUID,
        name: Optional[str] = None,
        description: Optional[str] = None,
        avatar_url: Optional[str] = None,
        settings: Optional[dict] = None
    ) -> Team:
        """
        Update team details.
        
        Args:
            team_id: Team ID
            updated_by: User performing update
            name: New team name
            description: New description
            avatar_url: New avatar URL
            settings: New settings
            
        Returns:
            Updated team
            
        Raises:
            TeamNotFoundError: If team not found
            PermissionDeniedError: If user cannot update team
        """
        # Check if team exists
        team = await self.uow.teams.get(team_id)
        if not team:
            raise TeamNotFoundError(f"Team {team_id} not found")

        # Check permissions
        if not await self.is_team_admin(team_id, updated_by):
            raise PermissionDeniedError("Only admins can update team")

        # Prepare update data
        update_data = {}
        if name is not None:
            update_data['name'] = name
        if description is not None:
            update_data['description'] = description
        if avatar_url is not None:
            update_data['avatar_url'] = avatar_url

        # Update team
        if update_data:
            team = await self.uow.teams.update(team_id, **update_data)

        # Update settings separately to merge
        if settings is not None:
            team = await self.uow.teams.update_settings(team_id, settings)

        # Log audit event
        log_audit_event(
            event_type=AuditEventType.TEAM_UPDATED,
            severity=AuditSeverity.LOW,
            details={
                'team_id': str(team_id),
                'updated_by': str(updated_by),
                'changes': list(update_data.keys())
            }
        )

        await self.uow.commit()

        logger.info(
            "Team updated",
            team_id=team_id,
            updated_by=updated_by
        )

        return team

    async def get_user_teams(
        self,
        user_id: UUID,
        only_active: bool = True
    ) -> list[Team]:
        """
        Get all teams a user is a member of.
        
        Args:
            user_id: User ID
            only_active: Include only active teams
            
        Returns:
            List of teams
        """
        return await self.uow.teams.get_user_teams(user_id, only_active)

    async def get_user_teams_paginated(
        self,
        user_id: UUID,
        only_active: bool = True,
        skip: int = 0,
        limit: int = 20
    ) -> list[Team]:
        """
        Get paginated teams a user is a member of.
        
        Args:
            user_id: User ID
            only_active: Include only active teams
            skip: Number of items to skip
            limit: Maximum items to return
            
        Returns:
            List of teams
        """
        from sqlalchemy import and_, select
        from sqlalchemy.orm import selectinload
        
        stmt = select(Team).join(TeamMember).where(
            and_(
                Team.tenant_id == self.uow.tenant_id,
                TeamMember.user_id == user_id,
                TeamMember.is_active == True
            )
        )
        
        if only_active:
            stmt = stmt.where(Team.is_active == True)
            
        stmt = stmt.order_by(Team.created_at.desc())
        stmt = stmt.offset(skip).limit(limit)
        stmt = stmt.options(selectinload(Team.creator))
        
        result = await self.uow.session.execute(stmt)
        return list(result.scalars().all())

    async def count_user_teams(
        self,
        user_id: UUID,
        only_active: bool = True
    ) -> int:
        """
        Count teams a user is a member of.
        
        Args:
            user_id: User ID
            only_active: Include only active teams
            
        Returns:
            Number of teams
        """
        from sqlalchemy import and_, func, select
        
        stmt = select(func.count(Team.id)).join(TeamMember).where(
            and_(
                Team.tenant_id == self.uow.tenant_id,
                TeamMember.user_id == user_id,
                TeamMember.is_active == True
            )
        )
        
        if only_active:
            stmt = stmt.where(Team.is_active == True)
            
        result = await self.uow.session.execute(stmt)
        return result.scalar() or 0

    async def get_team_members(
        self,
        team_id: UUID,
        only_active: bool = True,
        skip: int = 0,
        limit: int = 100
    ) -> list[TeamMember]:
        """
        Get members of a team.
        
        Args:
            team_id: Team ID
            only_active: Include only active members
            skip: Pagination offset
            limit: Pagination limit
            
        Returns:
            List of team members
        """
        return await self.uow.team_members.get_team_members(
            team_id=team_id,
            only_active=only_active,
            skip=skip,
            limit=limit
        )

    async def is_team_admin(self, team_id: UUID, user_id: UUID) -> bool:
        """
        Check if user is team admin or owner.
        
        Args:
            team_id: Team ID
            user_id: User ID
            
        Returns:
            True if user is admin or owner
        """
        member = await self.uow.team_members.get_member(team_id, user_id)
        if not member or not member.is_active:
            return False
        return member.role in ['owner', 'admin']

    async def is_team_member(self, team_id: UUID, user_id: UUID) -> bool:
        """
        Check if user is a team member.
        
        Args:
            team_id: Team ID
            user_id: User ID
            
        Returns:
            True if user is an active member
        """
        member = await self.uow.team_members.get_member(team_id, user_id)
        return member is not None and member.is_active

    async def update_member_role(
        self,
        team_id: UUID,
        user_id: UUID,
        new_role: str,
        updated_by: UUID,
        permissions: Optional[list[str]] = None
    ) -> TeamMember:
        """
        Update a member's role.
        
        Args:
            team_id: Team ID
            user_id: User ID to update
            new_role: New role
            updated_by: User performing update
            permissions: Optional new permissions
            
        Returns:
            Updated team member
            
        Raises:
            TeamNotFoundError: If team not found
            PermissionDeniedError: If user cannot update roles
            LastAdminError: If demoting last admin
        """
        # Check if team exists
        team = await self.uow.teams.get(team_id)
        if not team:
            raise TeamNotFoundError(f"Team {team_id} not found")

        # Check permissions
        if not await self.is_team_admin(team_id, updated_by):
            raise PermissionDeniedError("Only admins can update member roles")

        # Get current member
        member = await self.uow.team_members.get_member(team_id, user_id)
        if not member:
            raise ValueError("User is not a team member")

        # Check if demoting last admin
        if member.role in ['owner', 'admin'] and new_role not in ['owner', 'admin']:
            admins = await self.uow.team_members.get_team_admins(team_id)
            active_admins = [m for m in admins if m.is_active and m.role in ['owner', 'admin']]
            if len(active_admins) <= 1:
                raise LastAdminError("Cannot demote the last admin")

        # Update role
        updated_member = await self.uow.team_members.update_member_role(
            team_id=team_id,
            user_id=user_id,
            role=new_role,
            permissions=permissions
        )

        # Log audit event
        log_audit_event(
            event_type=AuditEventType.TEAM_MEMBER_ROLE_CHANGED,
            severity=AuditSeverity.MEDIUM,
            details={
                'team_id': str(team_id),
                'user_id': str(user_id),
                'old_role': member.role,
                'new_role': new_role,
                'updated_by': str(updated_by)
            }
        )

        await self.uow.commit()

        logger.info(
            "Member role updated",
            team_id=team_id,
            user_id=user_id,
            old_role=member.role,
            new_role=new_role
        )

        return updated_member

    async def delete_team(
        self,
        team_id: UUID,
        deleted_by: UUID
    ) -> bool:
        """
        Delete a team (soft delete).
        
        Args:
            team_id: Team ID
            deleted_by: User performing deletion
            
        Returns:
            True if deleted successfully
            
        Raises:
            TeamNotFoundError: If team not found
            PermissionDeniedError: If user cannot delete team
        """
        # Check if team exists
        team = await self.uow.teams.get(team_id)
        if not team:
            raise TeamNotFoundError(f"Team {team_id} not found")

        # Only owner can delete team
        member = await self.uow.team_members.get_member(team_id, deleted_by)
        if not member or member.role != 'owner':
            raise PermissionDeniedError("Only team owner can delete team")

        # Soft delete
        await self.uow.teams.update(team_id, is_active=False)

        # Log audit event
        log_audit_event(
            event_type=AuditEventType.TEAM_DELETED,
            severity=AuditSeverity.HIGH,
            details={
                'team_id': str(team_id),
                'team_name': team.name,
                'deleted_by': str(deleted_by)
            }
        )

        await self.uow.commit()

        logger.info(
            "Team deleted",
            team_id=team_id,
            deleted_by=deleted_by
        )

        return True
