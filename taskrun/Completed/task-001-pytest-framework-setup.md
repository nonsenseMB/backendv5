# Task 001: Setup Pytest Framework

## Priority: HIGH - Foundation Task
**Estimated Time**: 2-3 hours  
**Dependencies**: None  
**Blocking**: All other test tasks

## Why This Task is Critical

Currently, the test suite uses plain Python scripts with print statements instead of a proper testing framework. This approach has several critical problems:

1. **No assertions** - Tests can't actually fail, they just print output
2. **No test discovery** - Can't run all tests with a single command
3. **No test reports** - No way to track test coverage or failures
4. **No parallel execution** - Tests run slowly, one at a time
5. **No fixtures** - Test setup code is duplicated everywhere

## What Needs to Be Done

### 1. Install Testing Dependencies

Add to `pyproject.toml`:
```toml
[tool.poetry.group.test.dependencies]
pytest = "^8.0.0"
pytest-asyncio = "^0.23.0"
pytest-cov = "^4.1.0"
pytest-xdist = "^3.5.0"  # For parallel test execution
pytest-mock = "^3.12.0"
pytest-timeout = "^2.2.0"
factory-boy = "^3.3.0"  # For test data factories
```

Run: `poetry install --with test`

### 2. Configure Pytest

Create `pytest.ini` in project root:
```ini
[tool:pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
asyncio_mode = auto
addopts = 
    -ra
    --strict-markers
    --ignore=tests/integration/test_all_models.py
    --cov=src
    --cov-branch
    --cov-report=term-missing:skip-covered
    --cov-report=html:htmlcov
    --cov-report=xml
    --cov-fail-under=80
markers =
    slow: marks tests as slow (deselect with '-m "not slow"')
    integration: marks tests as integration tests
    unit: marks tests as unit tests
    security: marks tests as security tests
```

### 3. Update pyproject.toml Testing Configuration

```toml
[tool.pytest.ini_options]
minversion = "6.0"
testpaths = ["tests"]
filterwarnings = [
    "error",
    "ignore::UserWarning",
    "ignore::DeprecationWarning"
]

[tool.coverage.run]
source = ["src"]
omit = [
    "*/tests/*",
    "*/migrations/*",
    "*/__init__.py"
]

[tool.coverage.report]
precision = 2
show_missing = true
skip_covered = true
```

### 4. Create Test Runner Script

Create `run_tests.py`:
```python
#!/usr/bin/env python3
"""Test runner with different test suites."""
import sys
import subprocess

def run_tests(test_type="all"):
    """Run tests based on type."""
    commands = {
        "unit": "pytest -m unit -v",
        "integration": "pytest -m integration -v", 
        "security": "pytest -m security -v",
        "fast": "pytest -m 'not slow' -v",
        "all": "pytest -v",
        "coverage": "pytest --cov --cov-report=html",
        "parallel": "pytest -n auto -v"
    }
    
    cmd = commands.get(test_type, commands["all"])
    return subprocess.call(cmd.split())

if __name__ == "__main__":
    test_type = sys.argv[1] if len(sys.argv) > 1 else "all"
    sys.exit(run_tests(test_type))
```

### 5. Create Base Test Configuration

Update `tests/conftest.py`:
```python
"""Global pytest configuration and fixtures."""
import asyncio
import pytest
from typing import AsyncGenerator, Generator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from fastapi.testclient import TestClient
from httpx import AsyncClient

from src.main import app
from src.infrastructure.database.base import Base
from src.core.config import settings

# Override settings for testing
settings.DATABASE_URL = "postgresql+asyncpg://test:test@localhost/test_db"
settings.TESTING = True

@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="function")
async def db_engine():
    """Create test database engine."""
    engine = create_async_engine(
        settings.DATABASE_URL,
        echo=False,
        pool_pre_ping=True
    )
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield engine
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    
    await engine.dispose()

@pytest.fixture(scope="function")
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create database session for tests."""
    async_session = async_sessionmaker(
        db_engine,
        class_=AsyncSession,
        expire_on_commit=False
    )
    
    async with async_session() as session:
        yield session
        await session.rollback()

@pytest.fixture
def client() -> TestClient:
    """Create test client."""
    return TestClient(app)

@pytest.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """Create async test client."""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
```

### 6. Create Makefile Commands

Add to `Makefile`:
```makefile
# Testing commands
test:
	@python run_tests.py all

test-unit:
	@python run_tests.py unit

test-integration:
	@python run_tests.py integration

test-security:
	@python run_tests.py security

test-coverage:
	@python run_tests.py coverage
	@echo "Opening coverage report..."
	@open htmlcov/index.html

test-watch:
	@ptw -- -v

test-parallel:
	@python run_tests.py parallel
```

## Success Criteria

1. ✅ Can run `pytest` and discover all tests
2. ✅ Tests use assertions instead of print statements
3. ✅ Test coverage reports are generated
4. ✅ Can run specific test categories (unit, integration, etc.)
5. ✅ Database is properly isolated between tests
6. ✅ Async tests work correctly
7. ✅ Can run tests in parallel for speed

## Next Steps

After completing this task:
1. All existing tests need to be converted to pytest format (Task 002)
2. Test fixtures need to be created (Task 002)
3. Individual test suites can be developed (Tasks 003-010)

## Notes

- Use `pytest-xdist` for parallel test execution to speed up test runs
- Configure coverage to fail builds if coverage drops below 80%
- Set up different test markers for organizing test types
- Ensure all async tests are properly handled with pytest-asyncio