"""Unit tests for request context management."""
import asyncio
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from src.core.context import (
    RequestContext,
    RequestContextManager,
    UserContext,
    UserContextManager,
    clear_request_context,
    clear_tenant_context,
    clear_user_context,
    create_request_id,
    get_request_context,
    get_tenant_context,
    get_user_context,
    require_request_context,
    require_tenant_context,
    require_user_context,
    set_request_context,
    set_tenant_context,
    set_user_context,
    update_request_context,
    update_user_context,
)


class TestRequestContext:
    """Test request context management."""

    def test_create_request_id(self):
        """Test request ID generation."""
        request_id = create_request_id()
        assert isinstance(request_id, str)
        assert len(request_id) == 36  # UUID format
        
        # Ensure unique IDs
        request_id2 = create_request_id()
        assert request_id != request_id2

    def test_request_context_lifecycle(self):
        """Test setting, getting, and clearing request context."""
        # Initially no context
        assert get_request_context() is None
        
        # Create and set context
        context = RequestContext(
            request_id="test-123",
            user_id="user-456",
            tenant_id="tenant-789",
            session_id="session-abc",
            permissions=["read", "write"],
            ip_address="192.168.1.1"
        )
        set_request_context(context)
        
        # Retrieve context
        retrieved = get_request_context()
        assert retrieved is not None
        assert retrieved.request_id == "test-123"
        assert retrieved.user_id == "user-456"
        assert retrieved.tenant_id == "tenant-789"
        assert retrieved.permissions == ["read", "write"]
        
        # Clear context
        clear_request_context()
        assert get_request_context() is None

    def test_require_request_context(self):
        """Test requiring request context."""
        # No context should raise
        with pytest.raises(RuntimeError, match="No request context set"):
            require_request_context()
        
        # With context should return it
        context = RequestContext(
            request_id="test-123",
            user_id="user-456",
            tenant_id="tenant-789",
            session_id="session-abc"
        )
        set_request_context(context)
        
        required = require_request_context()
        assert required.request_id == "test-123"
        
        clear_request_context()

    def test_update_request_context(self):
        """Test updating request context fields."""
        context = RequestContext(
            request_id="test-123",
            user_id="user-456",
            tenant_id="tenant-789",
            session_id="session-abc"
        )
        set_request_context(context)
        
        # Update existing fields
        update_request_context(
            permissions=["admin"],
            ip_address="10.0.0.1",
            method="POST"
        )
        
        updated = get_request_context()
        assert updated.permissions == ["admin"]
        assert updated.ip_address == "10.0.0.1"
        assert updated.method == "POST"
        
        # Update with extra fields
        update_request_context(custom_field="custom_value")
        assert updated.extra["custom_field"] == "custom_value"
        
        clear_request_context()

    def test_request_context_manager(self):
        """Test RequestContextManager for temporary context switching."""
        # Set initial context
        context1 = RequestContext(
            request_id="req-1",
            user_id="user-1",
            tenant_id="tenant-1",
            session_id="session-1"
        )
        set_request_context(context1)
        
        # Use context manager for temporary switch
        context2 = RequestContext(
            request_id="req-2",
            user_id="user-2",
            tenant_id="tenant-2",
            session_id="session-2"
        )
        
        with RequestContextManager(context2):
            current = get_request_context()
            assert current.request_id == "req-2"
            assert current.user_id == "user-2"
        
        # Original context restored
        current = get_request_context()
        assert current.request_id == "req-1"
        assert current.user_id == "user-1"
        
        clear_request_context()

    def test_request_context_to_dict(self):
        """Test converting request context to dictionary."""
        context = RequestContext(
            request_id="test-123",
            user_id="user-456",
            tenant_id="tenant-789",
            session_id="session-abc",
            permissions=["read"],
            groups=["users"],
            ip_address="192.168.1.1",
            method="GET",
            path="/api/test"
        )
        
        context_dict = context.to_dict()
        assert context_dict["request_id"] == "test-123"
        assert context_dict["user_id"] == "user-456"
        assert context_dict["permissions"] == ["read"]
        assert context_dict["groups"] == ["users"]
        assert context_dict["method"] == "GET"
        assert "start_time" in context_dict


class TestUserContext:
    """Test user context management."""

    def test_user_context_lifecycle(self):
        """Test setting, getting, and clearing user context."""
        # Initially no context
        assert get_user_context() is None
        
        # Create and set context
        user_id = uuid.uuid4()
        context = UserContext(
            user_id=user_id,
            email="test@example.com",
            username="testuser",
            permissions=["users:read", "users:write"],
            groups=["developers"]
        )
        set_user_context(context)
        
        # Retrieve context
        retrieved = get_user_context()
        assert retrieved is not None
        assert retrieved.user_id == user_id
        assert retrieved.email == "test@example.com"
        assert retrieved.permissions == ["users:read", "users:write"]
        
        # Clear context
        clear_user_context()
        assert get_user_context() is None

    def test_user_permission_checks(self):
        """Test user permission checking methods."""
        context = UserContext(
            user_id=uuid.uuid4(),
            email="test@example.com",
            permissions=["users:read", "users:write", "teams:*", "admin"]
        )
        
        # Exact match
        assert context.has_permission("users:read") is True
        assert context.has_permission("users:delete") is False
        
        # Wildcard match
        assert context.has_permission("teams:read") is True
        assert context.has_permission("teams:write") is True
        assert context.has_permission("teams:delete") is True
        
        # Admin/superuser match
        assert context.has_permission("anything:here") is True  # admin permission
        
        # Multiple permissions
        assert context.has_any_permission(["users:delete", "users:read"]) is True
        assert context.has_any_permission(["users:delete", "posts:read"]) is False
        
        assert context.has_all_permissions(["users:read", "users:write"]) is True
        assert context.has_all_permissions(["users:read", "users:delete"]) is False

    def test_user_tenant_roles(self):
        """Test tenant role management."""
        context = UserContext(
            user_id=uuid.uuid4(),
            email="test@example.com",
            tenant_roles={
                "tenant-1": "owner",
                "tenant-2": "member"
            }
        )
        
        assert context.get_tenant_role("tenant-1") == "owner"
        assert context.get_tenant_role("tenant-2") == "member"
        assert context.get_tenant_role("tenant-3") is None

    def test_user_context_manager(self):
        """Test UserContextManager for temporary context switching."""
        # Set initial context
        context1 = UserContext(
            user_id=uuid.uuid4(),
            email="user1@example.com"
        )
        set_user_context(context1)
        
        # Use context manager for temporary switch
        context2 = UserContext(
            user_id=uuid.uuid4(),
            email="user2@example.com"
        )
        
        with UserContextManager(context2):
            current = get_user_context()
            assert current.email == "user2@example.com"
        
        # Original context restored
        current = get_user_context()
        assert current.email == "user1@example.com"
        
        clear_user_context()


class TestTenantContext:
    """Test tenant context management."""

    def test_tenant_context_lifecycle(self):
        """Test setting, getting, and clearing tenant context."""
        # Initially no context
        assert get_tenant_context() is None
        
        # Set context
        tenant_id = str(uuid.uuid4())
        set_tenant_context(tenant_id)
        
        # Retrieve context
        retrieved = get_tenant_context()
        assert retrieved == tenant_id
        
        # Clear context
        clear_tenant_context()
        assert get_tenant_context() is None

    def test_require_tenant_context(self):
        """Test requiring tenant context."""
        # No context should raise
        with pytest.raises(RuntimeError, match="No tenant context set"):
            require_tenant_context()
        
        # With context should return it
        tenant_id = str(uuid.uuid4())
        set_tenant_context(tenant_id)
        
        required = require_tenant_context()
        assert required == tenant_id
        
        clear_tenant_context()


class TestContextThreadSafety:
    """Test thread-safety of context variables."""

    @pytest.mark.asyncio
    async def test_context_isolation_between_tasks(self):
        """Test that context is isolated between concurrent tasks."""
        results = []
        
        async def task1():
            context = RequestContext(
                request_id="task1",
                user_id="user1",
                tenant_id="tenant1",
                session_id="session1"
            )
            set_request_context(context)
            
            # Simulate some async work
            await asyncio.sleep(0.01)
            
            # Check context hasn't changed
            current = get_request_context()
            results.append(("task1", current.request_id))
            
            clear_request_context()
        
        async def task2():
            context = RequestContext(
                request_id="task2",
                user_id="user2",
                tenant_id="tenant2",
                session_id="session2"
            )
            set_request_context(context)
            
            # Simulate some async work
            await asyncio.sleep(0.005)
            
            # Check context hasn't changed
            current = get_request_context()
            results.append(("task2", current.request_id))
            
            clear_request_context()
        
        # Run tasks concurrently
        await asyncio.gather(task1(), task2())
        
        # Verify each task maintained its own context
        assert len(results) == 2
        assert ("task1", "task1") in results
        assert ("task2", "task2") in results

    def test_context_isolation_between_threads(self):
        """Test that context is isolated between threads."""
        import threading
        
        results = []
        
        def thread_func(thread_id: str):
            context = RequestContext(
                request_id=f"thread-{thread_id}",
                user_id=f"user-{thread_id}",
                tenant_id=f"tenant-{thread_id}",
                session_id=f"session-{thread_id}"
            )
            set_request_context(context)
            
            # Check context
            current = get_request_context()
            results.append((thread_id, current.request_id))
            
            clear_request_context()
        
        # Create and start threads
        threads = []
        for i in range(3):
            thread = threading.Thread(target=thread_func, args=(str(i),))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # Verify each thread maintained its own context
        assert len(results) == 3
        assert ("0", "thread-0") in results
        assert ("1", "thread-1") in results
        assert ("2", "thread-2") in results


class TestContextIntegration:
    """Test context integration scenarios."""

    def test_full_context_setup(self):
        """Test setting up all context types together."""
        # Set up request context
        request_context = RequestContext(
            request_id="req-123",
            user_id="user-456",
            tenant_id="tenant-789",
            session_id="session-abc",
            permissions=["read", "write"]
        )
        set_request_context(request_context)
        
        # Set up tenant context
        set_tenant_context("tenant-789")
        
        # Set up user context
        user_context = UserContext(
            user_id=uuid.UUID("00000000-0000-0000-0000-000000000456"),
            email="test@example.com",
            permissions=["read", "write"],
            tenant_roles={"tenant-789": "admin"}
        )
        set_user_context(user_context)
        
        # Verify all contexts are available
        assert get_request_context().request_id == "req-123"
        assert get_tenant_context() == "tenant-789"
        assert get_user_context().email == "test@example.com"
        
        # Clear all contexts
        clear_request_context()
        clear_tenant_context()
        clear_user_context()
        
        # Verify all cleared
        assert get_request_context() is None
        assert get_tenant_context() is None
        assert get_user_context() is None