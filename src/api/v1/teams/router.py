"""
Team management API endpoints.
"""
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address

from src.api.dependencies.auth import get_current_user
from src.api.dependencies.database import get_uow
from src.core.auth.exceptions import PermissionDeniedError
from src.core.logging import get_logger
from src.infrastructure.database.models.user import User
from src.infrastructure.database.unit_of_work import UnitOfWork
from src.services.team_service import (
    AlreadyMemberError,
    LastAdminError,
    TeamLimitExceededError,
    TeamNotFoundError,
    TeamService,
)

from .schemas import (
    AddTeamMemberRequest,
    CreateTeamRequest,
    TeamDetailResponse,
    TeamListResponse,
    TeamMemberResponse,
    TeamResponse,
    TeamWithRoleResponse,
    UpdateMemberRoleRequest,
    UpdateTeamRequest,
)

logger = get_logger(__name__)

# Create rate limiter
limiter = Limiter(key_func=get_remote_address)

router = APIRouter(prefix="/teams", tags=["teams"])


@router.post(
    "",
    response_model=TeamResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new team",
    description="Create a new team. The creator automatically becomes the team owner.",
    dependencies=[Depends(limiter.limit("5/hour"))]
)
async def create_team(
    request: CreateTeamRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    req: Request
) -> TeamResponse:
    """Create a new team."""
    try:
        service = TeamService(uow)
        team = await service.create_team(
            name=request.name,
            slug=request.slug,
            created_by=current_user.id,
            description=request.description,
            avatar_url=request.avatar_url,
            settings=request.settings.model_dump() if request.settings else None
        )
        return TeamResponse.model_validate(team)

    except TeamLimitExceededError as e:
        logger.warning(
            "Team limit exceeded",
            user_id=current_user.id,
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        ) from e

    except ValueError as e:
        if "slug" in str(e):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(e)
            ) from e
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        ) from e

    except Exception as e:
        logger.error(
            "Failed to create team",
            user_id=current_user.id,
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create team"
        ) from e


@router.get(
    "",
    response_model=TeamListResponse,
    summary="List user's teams",
    description="Get all teams the current user is a member of"
)
async def list_teams(
    current_user: Annotated[User, Depends(get_current_user)],
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    only_active: bool = Query(True, description="Include only active teams"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page")
) -> TeamListResponse:
    """List user's teams."""
    try:
        service = TeamService(uow)
        
        # Get total count first
        total = await service.count_user_teams(
            user_id=current_user.id,
            only_active=only_active
        )
        
        # Get paginated teams with database-level pagination
        skip = (page - 1) * page_size
        teams = await service.get_user_teams_paginated(
            user_id=current_user.id,
            only_active=only_active,
            skip=skip,
            limit=page_size
        )

        # Get user's role for each team
        teams_with_roles = []
        for team in teams:
            member = await uow.team_members.get_member(team.id, current_user.id)
            team_dict = TeamWithRoleResponse.model_validate(team).model_dump()
            team_dict['user_role'] = member.role if member else None
            teams_with_roles.append(TeamWithRoleResponse(**team_dict))

        return TeamListResponse(
            teams=teams_with_roles,
            total=total,
            page=page,
            page_size=page_size
        )

    except Exception as e:
        logger.error(
            "Failed to list teams",
            user_id=current_user.id,
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list teams"
        )


@router.get(
    "/{team_id}",
    response_model=TeamDetailResponse,
    summary="Get team details",
    description="Get detailed information about a team"
)
async def get_team(
    team_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    uow: Annotated[UnitOfWork, Depends(get_uow)]
) -> TeamDetailResponse:
    """Get team details."""
    try:
        service = TeamService(uow)

        # Check if user is member
        if not await service.is_team_member(team_id, current_user.id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not a member of this team"
            )

        team = await uow.teams.get(team_id)
        if not team:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Team not found"
            )

        # Load creator
        await uow.session.refresh(team, ['creator'])

        return TeamDetailResponse.model_validate(team)

    except HTTPException:
        raise

    except Exception as e:
        logger.error(
            "Failed to get team",
            team_id=team_id,
            user_id=current_user.id,
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get team details"
        )


@router.put(
    "/{team_id}",
    response_model=TeamResponse,
    summary="Update team",
    description="Update team information. Only admins can update teams."
)
async def update_team(
    team_id: UUID,
    request: UpdateTeamRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    uow: Annotated[UnitOfWork, Depends(get_uow)]
) -> TeamResponse:
    """Update team."""
    try:
        service = TeamService(uow)

        team = await service.update_team(
            team_id=team_id,
            updated_by=current_user.id,
            name=request.name,
            description=request.description,
            avatar_url=request.avatar_url,
            settings=request.settings.model_dump() if request.settings else None
        )

        return TeamResponse.model_validate(team)

    except TeamNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Team not found"
        )

    except PermissionDeniedError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )

    except Exception as e:
        logger.error(
            "Failed to update team",
            team_id=team_id,
            user_id=current_user.id,
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update team"
        )


@router.delete(
    "/{team_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete team",
    description="Delete a team. Only the team owner can delete a team."
)
async def delete_team(
    team_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    uow: Annotated[UnitOfWork, Depends(get_uow)]
) -> None:
    """Delete team."""
    try:
        service = TeamService(uow)

        await service.delete_team(
            team_id=team_id,
            deleted_by=current_user.id
        )

    except TeamNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Team not found"
        )

    except PermissionDeniedError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )

    except Exception as e:
        logger.error(
            "Failed to delete team",
            team_id=team_id,
            user_id=current_user.id,
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete team"
        )


@router.post(
    "/{team_id}/members",
    response_model=TeamMemberResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add team member",
    description="Add a new member to the team. Only admins can add members.",
    dependencies=[Depends(limiter.limit("20/hour"))]
)
async def add_team_member(
    team_id: UUID,
    request: AddTeamMemberRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    req: Request
) -> TeamMemberResponse:
    """Add team member."""
    try:
        service = TeamService(uow)

        member = await service.add_member(
            team_id=team_id,
            user_id=request.user_id,
            role=request.role,
            invited_by=current_user.id,
            permissions=request.permissions
        )

        # Load user relationship
        await uow.session.refresh(member, ['user'])

        return TeamMemberResponse.model_validate(member)

    except TeamNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Team not found"
        )

    except PermissionDeniedError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )

    except AlreadyMemberError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e)
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

    except Exception as e:
        logger.error(
            "Failed to add team member",
            team_id=team_id,
            user_id=current_user.id,
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add team member"
        )


@router.get(
    "/{team_id}/members",
    response_model=list[TeamMemberResponse],
    summary="List team members",
    description="Get all members of a team"
)
async def list_team_members(
    team_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    uow: Annotated[UnitOfWork, Depends(get_uow)],
    only_active: bool = Query(True, description="Include only active members"),
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    limit: int = Query(100, ge=1, le=500, description="Maximum items to return")
) -> list[TeamMemberResponse]:
    """List team members."""
    try:
        service = TeamService(uow)

        # Check if user is member
        if not await service.is_team_member(team_id, current_user.id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not a member of this team"
            )

        members = await service.get_team_members(
            team_id=team_id,
            only_active=only_active,
            skip=skip,
            limit=limit
        )

        return [TeamMemberResponse.model_validate(member) for member in members]

    except HTTPException:
        raise

    except Exception as e:
        logger.error(
            "Failed to list team members",
            team_id=team_id,
            user_id=current_user.id,
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list team members"
        )


@router.put(
    "/{team_id}/members/{user_id}",
    response_model=TeamMemberResponse,
    summary="Update member role",
    description="Update a team member's role. Only admins can update roles."
)
async def update_member_role(
    team_id: UUID,
    user_id: UUID,
    request: UpdateMemberRoleRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    uow: Annotated[UnitOfWork, Depends(get_uow)]
) -> TeamMemberResponse:
    """Update member role."""
    try:
        service = TeamService(uow)

        member = await service.update_member_role(
            team_id=team_id,
            user_id=user_id,
            new_role=request.role,
            updated_by=current_user.id,
            permissions=request.permissions
        )

        # Load user relationship
        await uow.session.refresh(member, ['user'])

        return TeamMemberResponse.model_validate(member)

    except TeamNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Team not found"
        )

    except PermissionDeniedError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )

    except LastAdminError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e)
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

    except Exception as e:
        logger.error(
            "Failed to update member role",
            team_id=team_id,
            user_id=user_id,
            current_user_id=current_user.id,
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update member role"
        )


@router.delete(
    "/{team_id}/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove team member",
    description="Remove a member from the team. Admins can remove any member, members can remove themselves."
)
async def remove_team_member(
    team_id: UUID,
    user_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    uow: Annotated[UnitOfWork, Depends(get_uow)]
) -> None:
    """Remove team member."""
    try:
        service = TeamService(uow)

        success = await service.remove_member(
            team_id=team_id,
            user_id=user_id,
            removed_by=current_user.id
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Member not found"
            )

    except TeamNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Team not found"
        )

    except PermissionDeniedError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )

    except LastAdminError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e)
        )

    except HTTPException:
        raise

    except Exception as e:
        logger.error(
            "Failed to remove team member",
            team_id=team_id,
            user_id=user_id,
            current_user_id=current_user.id,
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to remove team member"
        )
