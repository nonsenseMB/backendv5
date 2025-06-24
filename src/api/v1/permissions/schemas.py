"""
Schemas for permission management endpoints.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class PermissionBase(BaseModel):
    """Base permission schema."""
    name: str = Field(..., description="Permission name (e.g., 'conversation.create')")
    resource: str = Field(..., description="Resource type (e.g., 'conversation')")
    action: str = Field(..., description="Action (e.g., 'create')")
    description: str | None = Field(None, description="Permission description")


class Permission(PermissionBase):
    """Full permission schema."""
    id: UUID
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class RoleBase(BaseModel):
    """Base role schema."""
    name: str = Field(..., description="Role name")
    description: str | None = Field(None, description="Role description")


class RoleCreate(RoleBase):
    """Schema for creating a role."""
    permissions: list[str] = Field(default=[], description="List of permission names")


class Role(RoleBase):
    """Full role schema."""
    id: UUID
    tenant_id: UUID
    is_system: bool
    permissions: list[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class UserRoleAssignment(BaseModel):
    """Schema for assigning roles to users."""
    role_id: UUID = Field(..., description="Role ID to assign")


class UserRoleResponse(BaseModel):
    """Schema for user role assignment response."""
    id: UUID
    user_id: UUID
    role_id: UUID
    tenant_id: UUID
    granted_by: UUID
    granted_at: datetime

    class Config:
        from_attributes = True


class ResourcePermissionGrant(BaseModel):
    """Schema for granting resource permissions."""
    resource_type: str = Field(..., description="Resource type (e.g., 'document')")
    resource_id: UUID = Field(..., description="Resource ID")
    permission: str = Field(..., description="Permission (e.g., 'read', 'write')")
    user_id: UUID | None = Field(None, description="User ID (if granting to user)")
    team_id: UUID | None = Field(None, description="Team ID (if granting to team)")
    expires_at: datetime | None = Field(None, description="Optional expiration time")


class ResourcePermissionResponse(BaseModel):
    """Schema for resource permission response."""
    id: UUID
    resource_type: str
    resource_id: UUID
    user_id: UUID | None
    team_id: UUID | None
    permission: str
    granted_by: UUID
    granted_at: datetime
    expires_at: datetime | None

    class Config:
        from_attributes = True


class PermissionCheckRequest(BaseModel):
    """Schema for permission check requests."""
    permission: str = Field(..., description="Permission to check")
    resource_type: str | None = Field(None, description="Resource type")
    resource_id: UUID | None = Field(None, description="Resource ID")


class PermissionCheckResponse(BaseModel):
    """Schema for permission check response."""
    has_permission: bool = Field(..., description="Whether user has the permission")
    reason: str | None = Field(None, description="Reason if permission denied")


class UserPermissionsResponse(BaseModel):
    """Schema for user permissions response."""
    user_id: UUID
    tenant_id: UUID
    roles: list[Role]
    permissions: list[str]
    resource_permissions: list[ResourcePermissionResponse]

    class Config:
        from_attributes = True
