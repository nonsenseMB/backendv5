"""
Pydantic schemas for team endpoints.
"""
import html
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from src.api.v1.users.schemas import UserBasicResponse


class TeamSettingsSchema(BaseModel):
    """Team settings schema."""
    notifications: bool = True
    auto_share_conversations: bool = False
    default_share_permission: str = Field(default="read", pattern="^(read|write)$")


class CreateTeamRequest(BaseModel):
    """Request schema for creating a team."""
    name: str = Field(..., min_length=1, max_length=255, description="Team name")
    slug: str = Field(..., min_length=1, max_length=255, pattern="^[a-z0-9-]+$", description="URL-friendly team identifier")
    description: str | None = Field(None, max_length=1000, description="Team description")
    avatar_url: str | None = Field(None, description="Team avatar URL")
    settings: TeamSettingsSchema | None = None

    @field_validator('name', 'description')
    @classmethod
    def sanitize_html(cls, v: str | None) -> str | None:
        """Sanitize HTML to prevent XSS."""
        if v is None:
            return v
        return html.escape(v)
    
    @field_validator('slug')
    @classmethod
    def validate_slug(cls, v: str) -> str:
        """Validate slug format."""
        if not v.replace('-', '').isalnum():
            raise ValueError("Slug must contain only lowercase letters, numbers, and hyphens")
        if v.startswith('-') or v.endswith('-'):
            raise ValueError("Slug cannot start or end with a hyphen")
        if '--' in v:
            raise ValueError("Slug cannot contain consecutive hyphens")
        # Check for reserved slugs
        reserved_slugs = {'admin', 'api', 'team', 'teams', 'user', 'users', 'system', 'config'}
        if v.lower() in reserved_slugs:
            raise ValueError(f"'{v}' is a reserved slug and cannot be used")
        return v.lower()


class UpdateTeamRequest(BaseModel):
    """Request schema for updating a team."""
    name: str | None = Field(None, min_length=1, max_length=255, description="Team name")
    description: str | None = Field(None, max_length=1000, description="Team description")
    avatar_url: str | None = Field(None, description="Team avatar URL")
    settings: TeamSettingsSchema | None = None
    
    @field_validator('name', 'description')
    @classmethod
    def sanitize_html(cls, v: str | None) -> str | None:
        """Sanitize HTML to prevent XSS."""
        if v is None:
            return v
        return html.escape(v)


class AddTeamMemberRequest(BaseModel):
    """Request schema for adding a team member."""
    user_id: UUID = Field(..., description="User ID to add to team")
    role: str = Field(default="member", pattern="^(owner|admin|member|viewer)$", description="Member role")
    permissions: list[str] | None = Field(default_factory=list, description="Additional permissions")


class UpdateMemberRoleRequest(BaseModel):
    """Request schema for updating member role."""
    role: str = Field(..., pattern="^(owner|admin|member|viewer)$", description="New member role")
    permissions: list[str] | None = Field(default_factory=list, description="Additional permissions")


class TeamResponse(BaseModel):
    """Basic team response."""
    id: UUID
    name: str
    slug: str
    description: str | None = None
    avatar_url: str | None = None
    member_count: int = 0
    is_active: bool = True
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class TeamWithRoleResponse(TeamResponse):
    """Team response with user's role."""
    user_role: str | None = Field(None, description="Current user's role in the team")


class TeamMemberResponse(BaseModel):
    """Team member response."""
    id: UUID
    user_id: UUID
    team_id: UUID
    role: str
    permissions: list[str] = []
    is_active: bool = True
    joined_at: datetime
    user: UserBasicResponse | None = None

    class Config:
        from_attributes = True


class TeamDetailResponse(TeamResponse):
    """Detailed team response."""
    settings: TeamSettingsSchema
    team_agent_id: UUID | None = None
    ws_channel_id: str | None = None
    active_conversations: int = 0
    created_by: UUID
    creator: UserBasicResponse | None = None
    metadata: dict[str, Any] = {}

    class Config:
        from_attributes = True


class TeamListResponse(BaseModel):
    """Response for team list."""
    teams: list[TeamWithRoleResponse]
    total: int
    page: int = 1
    page_size: int = 20
