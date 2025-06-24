"""
Unit tests for FastAPI dependencies.
"""
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies.auth import (
    get_current_active_user,
    get_current_user,
    get_current_user_id,
    get_current_verified_user,
    get_optional_user,
    require_auth,
)
from src.api.dependencies.permissions import (
    has_permission,
    require_all_permissions,
    require_any_permission,
    require_permission,
    require_tenant_permission,
)
from src.api.dependencies.session import (
    get_current_session,
    get_current_session_id,
    get_optional_session,
    get_session_metadata,
)
from src.api.dependencies.tenant import (
    get_current_tenant,
    get_current_tenant_id,
    get_optional_tenant,
    get_tenant_user,
    require_tenant,
    require_tenant_role,
)
from src.domain.auth.session_service import SessionInfo
from src.infrastructure.database.models.auth import User
from src.infrastructure.database.models.tenant import Tenant, TenantUser


class TestAuthDependencies:
    """Test authentication dependencies."""

    def test_get_current_user_id_success(self):
        """Test successful user ID extraction."""
        request = MagicMock(spec=Request)
        request.state.user_id = str(uuid.uuid4())
        request.url.path = "/api/test"
        
        user_id = get_current_user_id(request)
        assert isinstance(user_id, uuid.UUID)
        assert str(user_id) == request.state.user_id

    def test_get_current_user_id_missing(self):
        """Test missing user ID raises 401."""
        request = MagicMock(spec=Request)
        request.url.path = "/api/test"
        
        with pytest.raises(HTTPException) as exc_info:
            get_current_user_id(request)
        
        assert exc_info.value.status_code == 401
        assert "Authentication required" in exc_info.value.detail

    def test_get_current_user_id_invalid_format(self):
        """Test invalid user ID format raises 401."""
        request = MagicMock(spec=Request)
        request.state.user_id = "invalid-uuid"
        request.url.path = "/api/test"
        
        with pytest.raises(HTTPException) as exc_info:
            get_current_user_id(request)
        
        assert exc_info.value.status_code == 401
        assert "Invalid authentication state" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_get_current_user_success(self):
        """Test successful user retrieval."""
        user_id = uuid.uuid4()
        tenant_id = uuid.uuid4()
        
        # Mock request
        request = MagicMock(spec=Request)
        request.state.user_id = str(user_id)
        request.state.tenant_id = str(tenant_id)
        request.url.path = "/api/test"
        
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = user_id
        mock_user.is_active = True
        mock_user.email = "test@example.com"
        
        # Mock session and UnitOfWork
        mock_session = AsyncMock(spec=AsyncSession)
        mock_uow = MagicMock()
        mock_uow.users.get = AsyncMock(return_value=mock_user)
        mock_uow.users.update_last_seen = AsyncMock()
        mock_uow.commit = AsyncMock()
        
        with patch("src.api.dependencies.auth.UnitOfWork", return_value=mock_uow):
            user = await get_current_user(request, mock_session)
        
        assert user == mock_user
        mock_uow.users.get.assert_called_once_with(user_id)
        mock_uow.users.update_last_seen.assert_called_once_with(user_id)

    @pytest.mark.asyncio
    async def test_get_current_user_not_found(self):
        """Test user not found raises 401."""
        user_id = uuid.uuid4()
        
        request = MagicMock(spec=Request)
        request.state.user_id = str(user_id)
        request.url.path = "/api/test"
        
        mock_session = AsyncMock(spec=AsyncSession)
        mock_uow = MagicMock()
        mock_uow.users.get = AsyncMock(return_value=None)
        
        with patch("src.api.dependencies.auth.UnitOfWork", return_value=mock_uow):
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(request, mock_session)
        
        assert exc_info.value.status_code == 401
        assert "User not found" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_get_current_user_inactive(self):
        """Test inactive user raises 403."""
        user_id = uuid.uuid4()
        
        request = MagicMock(spec=Request)
        request.state.user_id = str(user_id)
        request.url.path = "/api/test"
        
        mock_user = MagicMock(spec=User)
        mock_user.id = user_id
        mock_user.is_active = False
        
        mock_session = AsyncMock(spec=AsyncSession)
        mock_uow = MagicMock()
        mock_uow.users.get = AsyncMock(return_value=mock_user)
        
        with patch("src.api.dependencies.auth.UnitOfWork", return_value=mock_uow):
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(request, mock_session)
        
        assert exc_info.value.status_code == 403
        assert "User account is inactive" in exc_info.value.detail

    def test_require_auth(self):
        """Test require_auth dependency."""
        user_id = uuid.uuid4()
        result = require_auth(user_id)
        assert result == user_id

    @pytest.mark.asyncio
    async def test_get_current_verified_user_success(self):
        """Test verified user check passes."""
        mock_user = MagicMock(spec=User)
        mock_user.is_verified = True
        
        user = await get_current_verified_user(mock_user)
        assert user == mock_user

    @pytest.mark.asyncio
    async def test_get_current_verified_user_unverified(self):
        """Test unverified user raises 403."""
        mock_user = MagicMock(spec=User)
        mock_user.is_verified = False
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_verified_user(mock_user)
        
        assert exc_info.value.status_code == 403
        assert "Email verification required" in exc_info.value.detail


class TestTenantDependencies:
    """Test tenant dependencies."""

    @pytest.mark.asyncio
    async def test_get_current_tenant_id_from_state(self):
        """Test tenant ID extraction from request state."""
        tenant_id = uuid.uuid4()
        
        request = MagicMock(spec=Request)
        request.state.tenant_id = str(tenant_id)
        request.url.path = "/api/test"
        
        result = await get_current_tenant_id(request)
        assert result == tenant_id

    @pytest.mark.asyncio
    async def test_get_current_tenant_id_from_context(self):
        """Test tenant ID extraction from context var."""
        tenant_id = uuid.uuid4()
        
        request = MagicMock(spec=Request)
        request.url.path = "/api/test"
        # No tenant_id in state
        
        with patch("src.api.dependencies.tenant.get_tenant_context", return_value=str(tenant_id)):
            result = await get_current_tenant_id(request)
        
        assert result == tenant_id

    @pytest.mark.asyncio
    async def test_get_current_tenant_id_missing(self):
        """Test missing tenant ID raises 400."""
        request = MagicMock(spec=Request)
        request.url.path = "/api/test"
        
        with patch("src.api.dependencies.tenant.get_tenant_context", return_value=None):
            with pytest.raises(HTTPException) as exc_info:
                await get_current_tenant_id(request)
        
        assert exc_info.value.status_code == 400
        assert "Tenant context required" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_get_current_tenant_success(self):
        """Test successful tenant retrieval."""
        tenant_id = uuid.uuid4()
        
        request = MagicMock(spec=Request)
        request.state.tenant_id = str(tenant_id)
        request.url.path = "/api/test"
        
        mock_tenant = MagicMock(spec=Tenant)
        mock_tenant.id = tenant_id
        mock_tenant.is_active = True
        mock_tenant.name = "Test Tenant"
        
        mock_session = AsyncMock(spec=AsyncSession)
        mock_uow = MagicMock()
        mock_uow.tenants.get = AsyncMock(return_value=mock_tenant)
        
        with patch("src.api.dependencies.tenant.UnitOfWork", return_value=mock_uow):
            tenant = await get_current_tenant(request, mock_session)
        
        assert tenant == mock_tenant

    @pytest.mark.asyncio
    async def test_get_tenant_user_success(self):
        """Test successful tenant-user retrieval."""
        user_id = uuid.uuid4()
        tenant_id = uuid.uuid4()
        
        mock_user = MagicMock(spec=User)
        mock_user.id = user_id
        
        mock_tenant = MagicMock(spec=Tenant)
        mock_tenant.id = tenant_id
        
        mock_tenant_user = MagicMock(spec=TenantUser)
        mock_tenant_user.user_id = user_id
        mock_tenant_user.tenant_id = tenant_id
        mock_tenant_user.is_active = True
        mock_tenant_user.role = "member"
        
        mock_session = AsyncMock(spec=AsyncSession)
        mock_uow = MagicMock()
        mock_uow.tenant_users.get_by = AsyncMock(return_value=[mock_tenant_user])
        
        with patch("src.api.dependencies.tenant.UnitOfWork", return_value=mock_uow):
            tenant_user = await get_tenant_user(mock_user, mock_tenant, mock_session)
        
        assert tenant_user == mock_tenant_user

    @pytest.mark.asyncio
    async def test_require_tenant_role_owner(self):
        """Test tenant role check for owner."""
        mock_tenant_user = MagicMock(spec=TenantUser)
        mock_tenant_user.role = "owner"
        mock_tenant_user.user_id = uuid.uuid4()
        mock_tenant_user.tenant_id = uuid.uuid4()
        
        check_role = await require_tenant_role("admin")
        result = await check_role(mock_tenant_user)
        
        assert result == mock_tenant_user

    @pytest.mark.asyncio
    async def test_require_tenant_role_insufficient(self):
        """Test insufficient tenant role raises 403."""
        mock_tenant_user = MagicMock(spec=TenantUser)
        mock_tenant_user.role = "viewer"
        mock_tenant_user.user_id = uuid.uuid4()
        mock_tenant_user.tenant_id = uuid.uuid4()
        
        check_role = await require_tenant_role("admin")
        
        with pytest.raises(HTTPException) as exc_info:
            await check_role(mock_tenant_user)
        
        assert exc_info.value.status_code == 403
        assert "Role 'admin' or higher required" in exc_info.value.detail


class TestPermissionDependencies:
    """Test permission dependencies."""

    @pytest.mark.asyncio
    async def test_require_permission_success(self):
        """Test successful permission check."""
        user_id = uuid.uuid4()
        
        request = MagicMock(spec=Request)
        request.state.permissions = ["users:read", "users:write"]
        
        mock_user = MagicMock(spec=User)
        mock_user.id = user_id
        
        check_permission = require_permission("users:read")
        result = await check_permission(request, mock_user)
        
        assert result == mock_user

    @pytest.mark.asyncio
    async def test_require_permission_wildcard(self):
        """Test wildcard permission matching."""
        user_id = uuid.uuid4()
        
        request = MagicMock(spec=Request)
        request.state.permissions = ["users:*"]
        
        mock_user = MagicMock(spec=User)
        mock_user.id = user_id
        
        check_permission = require_permission("users:read")
        result = await check_permission(request, mock_user)
        
        assert result == mock_user

    @pytest.mark.asyncio
    async def test_require_permission_admin(self):
        """Test admin permission grants all."""
        user_id = uuid.uuid4()
        
        request = MagicMock(spec=Request)
        request.state.permissions = ["admin"]
        
        mock_user = MagicMock(spec=User)
        mock_user.id = user_id
        
        check_permission = require_permission("any:permission")
        result = await check_permission(request, mock_user)
        
        assert result == mock_user

    @pytest.mark.asyncio
    async def test_require_permission_denied(self):
        """Test permission denied raises 403."""
        user_id = uuid.uuid4()
        
        request = MagicMock(spec=Request)
        request.state.permissions = ["users:read"]
        
        mock_user = MagicMock(spec=User)
        mock_user.id = user_id
        
        check_permission = require_permission("users:write")
        
        with pytest.raises(HTTPException) as exc_info:
            await check_permission(request, mock_user)
        
        assert exc_info.value.status_code == 403
        assert "Permission 'users:write' required" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_require_any_permission_success(self):
        """Test any permission check passes with one match."""
        user_id = uuid.uuid4()
        
        request = MagicMock(spec=Request)
        request.state.permissions = ["users:read"]
        
        mock_user = MagicMock(spec=User)
        mock_user.id = user_id
        
        check_permission = require_any_permission(["users:write", "users:read", "users:delete"])
        result = await check_permission(request, mock_user)
        
        assert result == mock_user

    @pytest.mark.asyncio
    async def test_require_all_permissions_success(self):
        """Test all permissions check passes."""
        user_id = uuid.uuid4()
        
        request = MagicMock(spec=Request)
        request.state.permissions = ["users:read", "users:write", "teams:read"]
        
        mock_user = MagicMock(spec=User)
        mock_user.id = user_id
        
        check_permission = require_all_permissions(["users:read", "users:write"])
        result = await check_permission(request, mock_user)
        
        assert result == mock_user

    @pytest.mark.asyncio
    async def test_require_all_permissions_missing(self):
        """Test all permissions check fails with missing permission."""
        user_id = uuid.uuid4()
        
        request = MagicMock(spec=Request)
        request.state.permissions = ["users:read"]
        
        mock_user = MagicMock(spec=User)
        mock_user.id = user_id
        
        check_permission = require_all_permissions(["users:read", "users:write"])
        
        with pytest.raises(HTTPException) as exc_info:
            await check_permission(request, mock_user)
        
        assert exc_info.value.status_code == 403
        assert "Missing: users:write" in exc_info.value.detail


class TestSessionDependencies:
    """Test session dependencies."""

    @pytest.mark.asyncio
    async def test_get_current_session_id_success(self):
        """Test successful session ID extraction."""
        session_id = uuid.uuid4()
        
        request = MagicMock(spec=Request)
        request.state.session_id = str(session_id)
        request.url.path = "/api/test"
        
        result = await get_current_session_id(request)
        assert result == session_id

    @pytest.mark.asyncio
    async def test_get_current_session_success(self):
        """Test successful session retrieval."""
        session_id = uuid.uuid4()
        user_id = uuid.uuid4()
        tenant_id = uuid.uuid4()
        
        request = MagicMock(spec=Request)
        request.state.session_id = str(session_id)
        request.url.path = "/api/test"
        
        mock_session_info = SessionInfo(
            session_id=session_id,
            user_id=user_id,
            tenant_id=tenant_id,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            is_active=True
        )
        
        mock_session_service = AsyncMock()
        mock_session_service.get_session = AsyncMock(return_value=mock_session_info)
        mock_session_service.validate_session = AsyncMock(return_value=True)
        
        session = await get_current_session(request, mock_session_service)
        
        assert session == mock_session_info
        mock_session_service.get_session.assert_called_once_with(session_id)
        mock_session_service.validate_session.assert_called_once_with(session_id)

    @pytest.mark.asyncio
    async def test_get_current_session_invalid(self):
        """Test invalid session raises 401."""
        session_id = uuid.uuid4()
        
        request = MagicMock(spec=Request)
        request.state.session_id = str(session_id)
        request.url.path = "/api/test"
        
        mock_session_info = MagicMock(spec=SessionInfo)
        
        mock_session_service = AsyncMock()
        mock_session_service.get_session = AsyncMock(return_value=mock_session_info)
        mock_session_service.validate_session = AsyncMock(return_value=False)
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_session(request, mock_session_service)
        
        assert exc_info.value.status_code == 401
        assert "Session expired or invalid" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_get_session_metadata(self):
        """Test session metadata extraction."""
        session_id = uuid.uuid4()
        user_id = uuid.uuid4()
        tenant_id = uuid.uuid4()
        
        mock_session_info = SessionInfo(
            session_id=session_id,
            user_id=user_id,
            tenant_id=tenant_id,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            is_active=True
        )
        
        metadata = await get_session_metadata(mock_session_info)
        
        assert metadata["session_id"] == str(session_id)
        assert metadata["user_id"] == str(user_id)
        assert metadata["tenant_id"] == str(tenant_id)
        assert metadata["is_active"] is True
        assert "created_at" in metadata
        assert "expires_at" in metadata