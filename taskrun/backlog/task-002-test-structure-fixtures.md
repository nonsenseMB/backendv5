first:
I've successfully set up the pytest framework for the nAI Backend v5 project. Here's
  what was accomplished:

  ✅ Completed Tasks:

  1. Testing Dependencies Added - Added pytest-xdist, pytest-mock, pytest-timeout, and
  factory-boy to pyproject.toml
  2. pytest.ini Created - Configured pytest with coverage settings, test markers, and 80%
  coverage requirement
  3. Enhanced pyproject.toml - Updated pytest and coverage configurations
  4. Test Runner Script - Created run_tests.py for different test execution modes
  5. Updated conftest.py - Added database fixtures and test configuration
  6. Makefile Commands - Added test-unit, test-integration, test-coverage, test-parallel,
  etc.
  7. Dependencies Installed - All new testing packages installed via poetry
  8. Verified Setup - Tests run successfully with coverage and parallel execution

  ✅ Success Criteria Met:

  1. ✅ Can run pytest and discover all tests
  2. ✅ Tests use assertions (existing tests already use them)
  3. ✅ Test coverage reports are generated
  4. ✅ Can run specific test categories (markers configured)
  5. ✅ Database is properly isolated between tests (fixtures created)
  6. ✅ Async tests work correctly
  7. ✅ Can run tests in parallel for speed

  The pytest framework is now fully set up and ready for use. Next steps would be to add
  the appropriate markers (@pytest.mark.unit, @pytest.mark.integration, etc.) to existing
  tests to enable filtered test runs.

# Task 002: Test Structure and Fixtures

## Priority: HIGH - Foundation Task
**Estimated Time**: 3-4 hours  
**Dependencies**: Task 001 (Pytest setup)  
**Blocking**: Tasks 003-010

## Why This Task is Critical

Without proper test structure and fixtures:
1. **Test data is hardcoded** - Makes tests brittle and hard to maintain
2. **No data isolation** - Tests can interfere with each other
3. **Duplicated setup code** - Same tenant/user creation in every test
4. **No test factories** - Creating complex test scenarios is difficult
5. **Poor organization** - Hard to find and run specific tests

## What Needs to Be Done

### 1. Create Proper Test Directory Structure

```
tests/
├── __init__.py
├── conftest.py                 # Root fixtures (from Task 001)
├── unit/                       # Fast, isolated tests
│   ├── __init__.py
│   ├── conftest.py            # Unit test fixtures
│   ├── models/
│   │   ├── __init__.py
│   │   ├── test_document.py
│   │   ├── test_knowledge.py
│   │   └── test_tool.py
│   └── repositories/
│       ├── __init__.py
│       ├── test_document_repository.py
│       ├── test_knowledge_repository.py
│       └── test_tool_repository.py
├── integration/                # Tests with database
│   ├── __init__.py
│   ├── conftest.py            # Integration fixtures
│   ├── test_document_flow.py
│   ├── test_knowledge_flow.py
│   └── test_tool_flow.py
├── security/                   # Security-specific tests
│   ├── __init__.py
│   ├── test_permissions.py
│   ├── test_sql_injection.py
│   └── test_auth_bypass.py
├── performance/               # Performance tests
│   ├── __init__.py
│   └── test_benchmarks.py
├── factories/                 # Test data factories
│   ├── __init__.py
│   ├── tenant.py
│   ├── user.py
│   ├── document.py
│   ├── knowledge.py
│   └── tool.py
└── utils/                     # Test utilities
    ├── __init__.py
    ├── assertions.py
    └── helpers.py
```

### 2. Create Test Factories

Create `tests/factories/base.py`:
```python
"""Base factory configuration."""
import factory
from factory.alchemy import SQLAlchemyModelFactory
from sqlalchemy.ext.asyncio import AsyncSession

class AsyncSQLAlchemyModelFactory(SQLAlchemyModelFactory):
    """Base factory for async SQLAlchemy models."""
    
    @classmethod
    async def create(cls, **kwargs):
        """Create and persist an instance."""
        instance = cls.build(**kwargs)
        cls._meta.sqlalchemy_session.add(instance)
        await cls._meta.sqlalchemy_session.flush()
        return instance
    
    @classmethod
    async def create_batch(cls, size, **kwargs):
        """Create multiple instances."""
        return [await cls.create(**kwargs) for _ in range(size)]
```

Create `tests/factories/tenant.py`:
```python
"""Tenant test factories."""
import factory
from faker import Faker
from .base import AsyncSQLAlchemyModelFactory
from src.infrastructure.database.models.tenant import Tenant

fake = Faker()

class TenantFactory(AsyncSQLAlchemyModelFactory):
    """Factory for creating test tenants."""
    
    class Meta:
        model = Tenant
        sqlalchemy_session_persistence = "flush"
    
    name = factory.LazyAttribute(lambda _: fake.company())
    domain = factory.LazyAttribute(lambda _: fake.domain_name())
    settings = factory.Dict({
        "max_users": 100,
        "features": ["documents", "knowledge", "tools"]
    })
    is_active = True
```

Create `tests/factories/user.py`:
```python
"""User test factories."""
import factory
from faker import Faker
from .base import AsyncSQLAlchemyModelFactory
from src.infrastructure.database.models.user import User

fake = Faker()

class UserFactory(AsyncSQLAlchemyModelFactory):
    """Factory for creating test users."""
    
    class Meta:
        model = User
        sqlalchemy_session_persistence = "flush"
    
    email = factory.LazyAttribute(lambda _: fake.email())
    name = factory.LazyAttribute(lambda _: fake.name())
    tenant = factory.SubFactory(TenantFactory)
    tenant_id = factory.SelfAttribute("tenant.id")
    role = "user"
    is_active = True
    preferences = factory.Dict({
        "theme": "light",
        "language": "en"
    })
```

### 3. Create Core Test Fixtures

Create `tests/unit/conftest.py`:
```python
"""Unit test fixtures."""
import pytest
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

@pytest.fixture
def mock_session():
    """Mock database session."""
    session = AsyncMock()
    session.execute = AsyncMock()
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    return session

@pytest.fixture
def mock_tenant_id():
    """Generate test tenant ID."""
    return uuid4()

@pytest.fixture
def mock_user_id():
    """Generate test user ID."""
    return uuid4()
```

Create `tests/integration/conftest.py`:
```python
"""Integration test fixtures."""
import pytest
from tests.factories import TenantFactory, UserFactory, TeamFactory

@pytest.fixture
async def test_tenant(db_session):
    """Create test tenant."""
    TenantFactory._meta.sqlalchemy_session = db_session
    tenant = await TenantFactory.create()
    yield tenant
    # Cleanup handled by transaction rollback

@pytest.fixture
async def test_user(db_session, test_tenant):
    """Create test user."""
    UserFactory._meta.sqlalchemy_session = db_session
    user = await UserFactory.create(tenant_id=test_tenant.id)
    yield user

@pytest.fixture
async def test_team(db_session, test_tenant, test_user):
    """Create test team."""
    TeamFactory._meta.sqlalchemy_session = db_session
    team = await TeamFactory.create(
        tenant_id=test_tenant.id,
        created_by_id=test_user.id
    )
    yield team

@pytest.fixture
async def auth_headers(test_user):
    """Generate auth headers for test user."""
    # This would use your actual auth system
    token = generate_test_token(test_user)
    return {"Authorization": f"Bearer {token}"}
```

### 4. Create Test Utilities

Create `tests/utils/assertions.py`:
```python
"""Custom test assertions."""
from typing import Any, Dict
import json

def assert_valid_uuid(value: Any):
    """Assert value is a valid UUID."""
    assert value is not None
    assert len(str(value)) == 36
    assert str(value).count('-') == 4

def assert_timestamps(obj: Any):
    """Assert object has valid timestamps."""
    assert hasattr(obj, 'created_at')
    assert hasattr(obj, 'updated_at')
    assert obj.created_at is not None
    assert obj.updated_at is not None
    assert obj.created_at <= obj.updated_at

def assert_json_equal(actual: Dict, expected: Dict):
    """Assert JSON objects are equal."""
    assert json.dumps(actual, sort_keys=True) == json.dumps(expected, sort_keys=True)

def assert_permission_denied(response):
    """Assert response indicates permission denied."""
    assert response.status_code == 403
    assert "permission" in response.json()["detail"].lower()
```

Create `tests/utils/helpers.py`:
```python
"""Test helper functions."""
from typing import Dict, Any
import asyncio
from contextlib import asynccontextmanager

async def create_test_document(session, **kwargs):
    """Helper to create test document with defaults."""
    from tests.factories import DocumentFactory
    DocumentFactory._meta.sqlalchemy_session = session
    defaults = {
        "title": "Test Document",
        "content": {"type": "doc", "content": []},
        "document_type": "document"
    }
    defaults.update(kwargs)
    return await DocumentFactory.create(**defaults)

@asynccontextmanager
async def assert_max_queries(session, max_queries: int):
    """Assert maximum number of queries executed."""
    query_count = 0
    original_execute = session.execute
    
    async def counting_execute(*args, **kwargs):
        nonlocal query_count
        query_count += 1
        return await original_execute(*args, **kwargs)
    
    session.execute = counting_execute
    yield
    session.execute = original_execute
    
    assert query_count <= max_queries, f"Expected max {max_queries} queries, got {query_count}"
```

### 5. Convert Existing Tests

Example conversion from print-based to pytest:

**Before:**
```python
async def test_document_creation():
    print("Testing document creation...")
    doc = await uow.documents.create(...)
    print(f"✅ Created document: {doc.title}")
```

**After:**
```python
@pytest.mark.asyncio
async def test_document_creation(db_session, test_tenant, test_user):
    """Test creating a document."""
    # Arrange
    uow = UnitOfWork(db_session)
    doc_data = {
        "title": "Test Document",
        "tenant_id": test_tenant.id,
        "owner_id": test_user.id,
        "content": {"type": "doc", "content": []}
    }
    
    # Act
    doc = await uow.documents.create(**doc_data)
    await uow.commit()
    
    # Assert
    assert doc.id is not None
    assert doc.title == "Test Document"
    assert doc.tenant_id == test_tenant.id
    assert_timestamps(doc)
```

### 6. Create Test Configuration

Create `tests/test_config.py`:
```python
"""Test configuration."""
import os

# Test database URL
TEST_DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://test:test@localhost/test_nai_backend"
)

# Test settings
TEST_SETTINGS = {
    "TESTING": True,
    "DATABASE_URL": TEST_DATABASE_URL,
    "REDIS_URL": "redis://localhost:6379/1",
    "SECRET_KEY": "test-secret-key",
    "DEBUG": True,
    "LOG_LEVEL": "DEBUG"
}

# Performance test settings
PERFORMANCE_TEST_SETTINGS = {
    "LARGE_DATASET_SIZE": 1000,
    "CONCURRENT_USERS": 50,
    "TEST_DURATION_SECONDS": 60
}
```

## Success Criteria

1. ✅ Test directory structure is properly organized
2. ✅ All test factories are created and working
3. ✅ Core fixtures for tenant, user, team are available
4. ✅ Database session is properly isolated per test
5. ✅ Custom assertions make tests more readable
6. ✅ Existing tests are converted to pytest format
7. ✅ Test data creation is simple and maintainable

## Next Steps

After this task:
1. Unit tests can be written using mocks (Tasks 003-005)
2. Integration tests can use real database fixtures
3. Security tests can use auth fixtures (Task 006)
4. Performance tests can use data factories (Task 008)

## Notes

- Use factories for all test data creation
- Never hardcode UUIDs or IDs in tests
- Always cleanup test data (use transaction rollback)
- Keep fixtures focused and composable
- Use descriptive test names that explain what is being tested