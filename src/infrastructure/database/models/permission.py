"""
Permission and Authorization models for role-based and resource-based access control.
Implements tenant-scoped permission system as defined in task-130.
"""

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy import JSON

from ..base import BaseModel, TenantAwareModel


class Permission(BaseModel):
    """
    Defines available permissions in the system.
    Uses resource.action pattern (e.g., 'conversation.create').
    """
    __tablename__ = 'permissions'

    # Permission definition
    name = Column(String(255), unique=True, nullable=False)  # e.g., "conversation.create"
    resource = Column(String(100), nullable=False)  # e.g., "conversation"
    action = Column(String(100), nullable=False)    # e.g., "create"
    description = Column(Text, nullable=True)

    # Relationships
    roles = relationship("RolePermission", back_populates="permission")

    def __repr__(self):
        return f"<Permission(name='{self.name}', resource='{self.resource}', action='{self.action}')>"


class Role(TenantAwareModel):
    """
    Defines roles within a tenant.
    Supports both system roles and custom tenant-specific roles.
    """
    __tablename__ = 'roles'

    # Role definition
    name = Column(String(100), nullable=False)  # Admin, Member, Viewer
    description = Column(Text, nullable=True)
    is_system = Column(Boolean, default=False)  # System vs custom roles

    # Relationships
    permissions = relationship("RolePermission", back_populates="role", cascade="all, delete-orphan")
    user_roles = relationship("UserRole", back_populates="role", cascade="all, delete-orphan")

    # Constraints
    __table_args__ = (
        UniqueConstraint('tenant_id', 'name', name='_tenant_role_name_uc'),
    )

    def __repr__(self):
        return f"<Role(name='{self.name}', tenant_id={self.tenant_id}, is_system={self.is_system})>"


class RolePermission(BaseModel):
    """
    Many-to-many relationship between roles and permissions.
    """
    __tablename__ = 'role_permissions'

    # Foreign keys
    role_id = Column(UUID(as_uuid=True), ForeignKey('roles.id', ondelete='CASCADE'), nullable=False)
    permission_id = Column(UUID(as_uuid=True), ForeignKey('permissions.id', ondelete='CASCADE'), nullable=False)

    # Relationships
    role = relationship("Role", back_populates="permissions")
    permission = relationship("Permission", back_populates="roles")

    # Constraints
    __table_args__ = (
        UniqueConstraint('role_id', 'permission_id', name='_role_permission_uc'),
    )

    def __repr__(self):
        return f"<RolePermission(role_id={self.role_id}, permission_id={self.permission_id})>"


class UserRole(TenantAwareModel):
    """
    Assigns roles to users within a tenant.
    Tracks who granted the role and when.
    """
    __tablename__ = 'user_roles'

    # Assignment
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    role_id = Column(UUID(as_uuid=True), ForeignKey('roles.id', ondelete='CASCADE'), nullable=False)

    # Audit trail
    granted_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    granted_at = Column(DateTime, nullable=False, default=lambda: BaseModel.created_at.default.arg)

    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    role = relationship("Role", back_populates="user_roles")
    granter = relationship("User", foreign_keys=[granted_by])

    # Constraints
    __table_args__ = (
        UniqueConstraint('user_id', 'role_id', 'tenant_id', name='_user_role_tenant_uc'),
    )

    def __repr__(self):
        return f"<UserRole(user_id={self.user_id}, role_id={self.role_id}, tenant_id={self.tenant_id})>"


class ResourcePermission(TenantAwareModel):
    """
    Fine-grained resource-level permissions.
    Allows specific users or teams to access specific resources.
    """
    __tablename__ = 'resource_permissions'

    # Resource identification
    resource_type = Column(String(50), nullable=False)  # "document", "conversation", "agent"
    resource_id = Column(UUID(as_uuid=True), nullable=False)

    # Permission subject (either user or team, not both)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=True)
    team_id = Column(UUID(as_uuid=True), ForeignKey('teams.id', ondelete='CASCADE'), nullable=True)

    # Permission details
    permission = Column(String(50), nullable=False)  # "read", "write", "delete", "manage"

    # Audit trail
    granted_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    granted_at = Column(DateTime, nullable=False, default=lambda: BaseModel.created_at.default.arg)
    expires_at = Column(DateTime, nullable=True)

    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    team = relationship("Team", foreign_keys=[team_id])
    granter = relationship("User", foreign_keys=[granted_by])

    # Constraints
    __table_args__ = (
        UniqueConstraint(
            'resource_type', 'resource_id', 'user_id', 'team_id', 'permission', 'tenant_id',
            name='_resource_permission_uc'
        ),
    )

    def __repr__(self):
        subject = f"user_id={self.user_id}" if self.user_id else f"team_id={self.team_id}"
        return f"<ResourcePermission({subject}, resource={self.resource_type}:{self.resource_id}, permission='{self.permission}')>"