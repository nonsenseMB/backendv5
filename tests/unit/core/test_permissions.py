"""
Unit tests for the core permissions system.
Tests role-based and resource-based access control.
"""

import pytest
from datetime import datetime
from uuid import uuid4, UUID
from unittest.mock import Mock, AsyncMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.core.auth.permissions import (
    PermissionChecker,
    TenantPermissionValidator,
    SystemRole,
    SYSTEM_ROLE_PERMISSIONS,
    apply_tenant_filter
)
from src.infrastructure.database.models.permission import (
    Permission, ResourcePermission, Role, RolePermission, UserRole
)
from src.infrastructure.database.models.tenant import TenantUser
from src.infrastructure.database.models.team import TeamMember
from src.infrastructure.database.base import Base


class TestPermissionChecker:
    """Test the PermissionChecker class."""

    @pytest.fixture
    def mock_db(self):
        """Create mock database session."""
        return Mock()

    @pytest.fixture
    def permission_checker(self, mock_db):
        """Create PermissionChecker instance."""
        return PermissionChecker(mock_db)

    @pytest.fixture
    def test_user_id(self):
        """Test user ID."""
        return uuid4()

    @pytest.fixture
    def test_tenant_id(self):
        """Test tenant ID."""
        return uuid4()

    async def test_check_permission_with_role_permission(
        self, permission_checker, mock_db, test_user_id, test_tenant_id
    ):
        """Test permission check through role-based permissions."""
        permission = "conversation.create"
        
        # Mock database query chain
        mock_permission = Mock()
        mock_permission.name = permission
        
        mock_query = Mock()
        mock_query.join.return_value = mock_query
        mock_query.filter.return_value = mock_query
        mock_query.first.return_value = mock_permission
        
        mock_db.query.return_value = mock_query
        
        # Test permission check
        result = await permission_checker.check_permission(
            test_user_id, test_tenant_id, permission
        )
        
        assert result is True
        mock_db.query.assert_called_with(Permission)

    async def test_check_permission_with_wildcard_role(
        self, permission_checker, mock_db, test_user_id, test_tenant_id
    ):
        """Test permission check with wildcard role permissions."""
        permission = "conversation.create"
        
        # Mock database query to find wildcard permission
        mock_permission = Mock()
        mock_permission.name = "conversation.*"
        
        mock_query = Mock()
        mock_query.join.return_value = mock_query
        mock_query.filter.return_value = mock_query
        mock_query.first.return_value = mock_permission
        
        mock_db.query.return_value = mock_query
        
        result = await permission_checker.check_permission(
            test_user_id, test_tenant_id, permission
        )
        
        assert result is True

    async def test_check_permission_denied(
        self, permission_checker, mock_db, test_user_id, test_tenant_id
    ):
        """Test permission check when permission is denied."""
        permission = "conversation.delete"
        
        # Mock no permission found
        mock_query = Mock()
        mock_query.join.return_value = mock_query
        mock_query.filter.return_value = mock_query
        mock_query.first.return_value = None
        
        mock_db.query.return_value = mock_query
        
        result = await permission_checker.check_permission(
            test_user_id, test_tenant_id, permission
        )
        
        assert result is False

    async def test_check_resource_permission_direct_user(
        self, permission_checker, mock_db, test_user_id, test_tenant_id
    ):
        """Test resource permission check with direct user permission."""
        permission = "document.read"
        resource_type = "document"
        resource_id = uuid4()
        
        # Mock role permission not found, but resource permission found
        mock_query_role = Mock()
        mock_query_role.join.return_value = mock_query_role
        mock_query_role.filter.return_value = mock_query_role
        mock_query_role.first.return_value = None
        
        mock_resource_permission = Mock()
        mock_query_resource = Mock()
        mock_query_resource.filter.return_value = mock_query_resource
        mock_query_resource.first.return_value = mock_resource_permission
        
        # Configure query method to return different mocks based on model
        def query_side_effect(model):
            if model == Permission:
                return mock_query_role
            elif model == ResourcePermission:
                return mock_query_resource
            return Mock()
        
        mock_db.query.side_effect = query_side_effect
        
        result = await permission_checker.check_permission(
            test_user_id, test_tenant_id, permission,
            resource_type=resource_type, resource_id=resource_id
        )
        
        assert result is True

    async def test_check_resource_permission_team_permission(
        self, permission_checker, mock_db, test_user_id, test_tenant_id
    ):
        """Test resource permission check through team membership."""
        permission = "document.edit"
        resource_type = "document"
        resource_id = uuid4()
        
        # Mock role permission not found
        mock_query_role = Mock()
        mock_query_role.join.return_value = mock_query_role
        mock_query_role.filter.return_value = mock_query_role
        mock_query_role.first.return_value = None
        
        # Mock direct user permission not found
        mock_query_user_resource = Mock()
        mock_query_user_resource.filter.return_value = mock_query_user_resource
        mock_query_user_resource.first.return_value = None
        
        # Mock team permission found
        mock_team_permission = Mock()
        mock_query_team_resource = Mock()
        mock_query_team_resource.join.return_value = mock_query_team_resource
        mock_query_team_resource.filter.return_value = mock_query_team_resource
        mock_query_team_resource.first.return_value = mock_team_permission
        
        # Track calls to determine which query to return
        call_count = 0
        def query_side_effect(model):
            nonlocal call_count
            call_count += 1
            if model == Permission:
                return mock_query_role
            elif model == ResourcePermission:
                if call_count == 2:  # First ResourcePermission call (user)
                    return mock_query_user_resource
                else:  # Second ResourcePermission call (team)
                    return mock_query_team_resource
            return Mock()
        
        mock_db.query.side_effect = query_side_effect
        
        result = await permission_checker.check_permission(
            test_user_id, test_tenant_id, permission,
            resource_type=resource_type, resource_id=resource_id
        )
        
        assert result is True

    async def test_get_user_permissions(
        self, permission_checker, mock_db, test_user_id, test_tenant_id
    ):
        """Test retrieving all user permissions."""
        # Mock permissions
        mock_permissions = [
            ("conversation.create",),
            ("conversation.read",),
            ("document.read",),
        ]
        
        mock_query = Mock()
        mock_query.join.return_value = mock_query
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = mock_permissions
        
        mock_db.query.return_value = mock_query
        
        permissions = await permission_checker.get_user_permissions(
            test_user_id, test_tenant_id
        )
        
        expected_permissions = {
            "conversation.create",
            "conversation.read", 
            "document.read"
        }
        assert permissions == expected_permissions

    async def test_get_user_roles(
        self, permission_checker, mock_db, test_user_id, test_tenant_id
    ):
        """Test retrieving user roles."""
        # Mock roles
        role_id = uuid4()
        mock_role = Mock()
        mock_role.id = role_id
        mock_role.name = "admin"
        mock_role.description = "Administrator"
        mock_role.is_system = True
        
        mock_query = Mock()
        mock_query.join.return_value = mock_query
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = [mock_role]
        
        mock_db.query.return_value = mock_query
        
        roles = await permission_checker.get_user_roles(
            test_user_id, test_tenant_id
        )
        
        expected_roles = [{
            "id": str(role_id),
            "name": "admin",
            "description": "Administrator",
            "is_system": True
        }]
        assert roles == expected_roles


class TestTenantPermissionValidator:
    """Test the TenantPermissionValidator class."""

    @pytest.fixture
    def mock_db(self):
        """Create mock database session."""
        return Mock()

    @pytest.fixture
    def validator(self, mock_db):
        """Create TenantPermissionValidator instance."""
        return TenantPermissionValidator(mock_db)

    @pytest.fixture
    def test_user_id(self):
        """Test user ID."""
        return uuid4()

    @pytest.fixture
    def test_tenant_id(self):
        """Test tenant ID."""
        return uuid4()

    async def test_validate_tenant_access_success(
        self, validator, mock_db, test_user_id, test_tenant_id
    ):
        """Test successful tenant access validation."""
        # Mock tenant user found
        mock_tenant_user = Mock()
        mock_tenant_user.user_id = test_user_id
        mock_tenant_user.tenant_id = test_tenant_id
        mock_tenant_user.is_active = True
        
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.first.return_value = mock_tenant_user
        
        mock_db.query.return_value = mock_query
        
        result = await validator.validate_tenant_access(
            test_user_id, test_tenant_id
        )
        
        assert result is True

    async def test_validate_tenant_access_denied(
        self, validator, mock_db, test_user_id, test_tenant_id
    ):
        """Test tenant access validation when user not in tenant."""
        # Mock no tenant user found
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.first.return_value = None
        
        mock_db.query.return_value = mock_query
        
        result = await validator.validate_tenant_access(
            test_user_id, test_tenant_id
        )
        
        assert result is False

    async def test_validate_tenant_access_with_resource(
        self, validator, mock_db, test_user_id, test_tenant_id
    ):
        """Test tenant access validation with resource verification."""
        resource_type = "document"
        resource_id = uuid4()
        
        # Mock tenant user found
        mock_tenant_user = Mock()
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.first.return_value = mock_tenant_user
        
        mock_db.query.return_value = mock_query
        
        result = await validator.validate_tenant_access(
            test_user_id, test_tenant_id, resource_type, resource_id
        )
        
        # Currently returns True as placeholder implementation
        assert result is True


class TestSystemRoles:
    """Test system role configuration."""

    def test_system_role_enum(self):
        """Test SystemRole enum values."""
        assert SystemRole.ADMIN == "admin"
        assert SystemRole.MEMBER == "member"
        assert SystemRole.VIEWER == "viewer"

    def test_system_role_permissions_coverage(self):
        """Test that all system roles have permissions defined."""
        for role in SystemRole:
            assert role in SYSTEM_ROLE_PERMISSIONS
            assert len(SYSTEM_ROLE_PERMISSIONS[role]) > 0

    def test_admin_permissions(self):
        """Test admin role has comprehensive permissions."""
        admin_perms = SYSTEM_ROLE_PERMISSIONS[SystemRole.ADMIN]
        
        # Admin should have manage permissions
        assert "tenant.manage" in admin_perms
        assert "user.manage" in admin_perms
        
        # Admin should have wildcard permissions
        assert "conversation.*" in admin_perms
        assert "document.*" in admin_perms

    def test_member_permissions(self):
        """Test member role has appropriate permissions."""
        member_perms = SYSTEM_ROLE_PERMISSIONS[SystemRole.MEMBER]
        
        # Member should have create/read/update but not manage
        assert "conversation.create" in member_perms
        assert "conversation.read" in member_perms
        assert "conversation.update" in member_perms
        assert "tenant.manage" not in member_perms

    def test_viewer_permissions(self):
        """Test viewer role has only read permissions."""
        viewer_perms = SYSTEM_ROLE_PERMISSIONS[SystemRole.VIEWER]
        
        # Viewer should only have read permissions
        for perm in viewer_perms:
            assert perm.endswith(".read") or perm == "agent.read"
        
        # Viewer should not have create/update/manage permissions
        create_perms = [p for p in viewer_perms if ".create" in p]
        update_perms = [p for p in viewer_perms if ".update" in p]
        manage_perms = [p for p in viewer_perms if ".manage" in p]
        
        assert len(create_perms) == 0
        assert len(update_perms) == 0
        assert len(manage_perms) == 0


class TestUtilityFunctions:
    """Test utility functions."""

    def test_apply_tenant_filter_with_tenant_id(self):
        """Test applying tenant filter to model with tenant_id."""
        mock_query = Mock()
        mock_model = Mock()
        mock_model.tenant_id = "tenant_field"
        test_tenant_id = uuid4()
        
        # Mock the filter method
        mock_query.filter.return_value = "filtered_query"
        
        result = apply_tenant_filter(mock_query, test_tenant_id, mock_model)
        
        # Should call filter with tenant_id
        mock_query.filter.assert_called_once()
        assert result == "filtered_query"

    def test_apply_tenant_filter_without_tenant_id(self):
        """Test applying tenant filter to model without tenant_id."""
        mock_query = Mock()
        mock_model = Mock()
        # Model doesn't have tenant_id attribute
        delattr(mock_model, 'tenant_id') if hasattr(mock_model, 'tenant_id') else None
        test_tenant_id = uuid4()
        
        result = apply_tenant_filter(mock_query, test_tenant_id, mock_model)
        
        # Should return original query unchanged
        mock_query.filter.assert_not_called()
        assert result == mock_query


class TestPermissionEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.fixture
    def mock_db(self):
        """Create mock database session."""
        return Mock()

    @pytest.fixture
    def permission_checker(self, mock_db):
        """Create PermissionChecker instance."""
        return PermissionChecker(mock_db)

    async def test_check_permission_with_invalid_uuid(self, permission_checker):
        """Test permission check with invalid UUID."""
        with pytest.raises((ValueError, TypeError)):
            await permission_checker.check_permission(
                "invalid-uuid", uuid4(), "test.permission"
            )

    async def test_check_permission_with_empty_permission(
        self, permission_checker, mock_db
    ):
        """Test permission check with empty permission string."""
        # Mock no permission found
        mock_query = Mock()
        mock_query.join.return_value = mock_query
        mock_query.filter.return_value = mock_query
        mock_query.first.return_value = None
        
        mock_db.query.return_value = mock_query
        
        result = await permission_checker.check_permission(
            uuid4(), uuid4(), ""
        )
        
        assert result is False

    async def test_check_permission_database_error(
        self, permission_checker, mock_db
    ):
        """Test permission check when database raises an error."""
        # Mock database error
        mock_db.query.side_effect = Exception("Database error")
        
        with pytest.raises(Exception, match="Database error"):
            await permission_checker.check_permission(
                uuid4(), uuid4(), "test.permission"
            )

    async def test_get_user_permissions_empty_result(
        self, permission_checker, mock_db
    ):
        """Test getting user permissions when user has no permissions."""
        # Mock empty result
        mock_query = Mock()
        mock_query.join.return_value = mock_query
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = []
        
        mock_db.query.return_value = mock_query
        
        permissions = await permission_checker.get_user_permissions(
            uuid4(), uuid4()
        )
        
        assert permissions == set()

    async def test_get_user_roles_empty_result(
        self, permission_checker, mock_db
    ):
        """Test getting user roles when user has no roles."""
        # Mock empty result
        mock_query = Mock()
        mock_query.join.return_value = mock_query
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = []
        
        mock_db.query.return_value = mock_query
        
        roles = await permission_checker.get_user_roles(
            uuid4(), uuid4()
        )
        
        assert roles == []