# Testing Documentation Guide

## Test Documentation Standards

### Test Function Documentation

```python
import pytest
from unittest.mock import Mock, patch

class TestUserService:
    """Test cases for UserService functionality."""
    
    @pytest.mark.asyncio
    async def test_create_user_success(self, user_service, mock_repository):
        """Test successful user creation.
        
        Given:
            - Valid user data
            - Available email address
        When:
            - create_user is called
        Then:
            - User is created in repository
            - Confirmation email is sent
            - User object is returned
        """
        # Arrange
        user_data = {"email": "test@example.com", "name": "Test User"}
        mock_repository.get_by_email.return_value = None
        
        # Act
        result = await user_service.create_user(user_data)
        
        # Assert
        assert result.email == user_data["email"]
        mock_repository.save.assert_called_once()
```

### Test Fixtures Documentation

```python
# conftest.py
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

@pytest.fixture
async def db_session():
    """Provide a transactional database session for tests.
    
    This fixture creates a new database session for each test
    and automatically rolls back all changes after the test completes.
    
    Yields:
        AsyncSession: Database session for testing
    """
    async with test_engine.begin() as conn:
        async with AsyncSession(bind=conn) as session:
            yield session
            await session.rollback()

@pytest.fixture
def mock_llm_client():
    """Mock LLM client for testing.
    
    Returns a mock client with pre-configured responses
    for common test scenarios.
    
    Returns:
        Mock: Configured mock LLM client
    """
    client = Mock()
    client.generate.return_value = "Mock response"
    return client
```

## Test Categories

### Unit Tests

```python
# tests/unit/test_document_processor.py
"""Unit tests for document processing functionality.

These tests verify individual components in isolation
using mocks for all external dependencies.
"""

def test_chunk_text():
    """Test text chunking algorithm."""
    processor = DocumentProcessor()
    text = "A" * 1500  # Text longer than chunk size
    
    chunks = processor.chunk_text(text, chunk_size=1000, overlap=100)
    
    assert len(chunks) == 2
    assert len(chunks[0]) == 1000
    assert chunks[0][-100:] == chunks[1][:100]  # Verify overlap
```

### Integration Tests

```python
# tests/integration/test_api_integration.py
"""Integration tests for API endpoints.

These tests verify that components work together correctly,
using real database connections but mocked external services.
"""

@pytest.mark.integration
async def test_message_flow(client, db_session):
    """Test complete message flow from API to database."""
    # Create conversation
    response = await client.post("/api/v1/conversations")
    conversation_id = response.json()["id"]
    
    # Send message
    response = await client.post(
        "/api/v1/messages",
        json={
            "content": "Hello",
            "conversation_id": conversation_id
        }
    )
    
    assert response.status_code == 201
    
    # Verify in database
    messages = await db_session.execute(
        select(Message).where(Message.conversation_id == conversation_id)
    )
    assert len(messages.all()) == 1
```

### End-to-End Tests

```python
# tests/e2e/test_user_workflows.py
"""End-to-end tests for complete user workflows.

These tests simulate real user interactions through the entire system,
including external services.
"""

@pytest.mark.e2e
@pytest.mark.slow
async def test_complete_chat_session():
    """Test a complete chat session from login to logout."""
    # Login
    token = await login_user("test@example.com", "password")
    
    # Create conversation
    conversation = await create_conversation(token)
    
    # Send messages
    messages = [
        "Hello, I need help with Python",
        "How do I read a CSV file?",
        "Thanks for the help!"
    ]
    
    for msg in messages:
        response = await send_message(token, conversation.id, msg)
        assert response.status_code == 201
        assert "content" in response.json()
```

## Test Data Management

### Test Data Factories

```python
# tests/factories.py
import factory
from factory.fuzzy import FuzzyText, FuzzyChoice

class UserFactory(factory.Factory):
    """Factory for creating test User instances."""
    
    class Meta:
        model = User
    
    id = factory.Faker("uuid4")
    email = factory.Faker("email")
    name = factory.Faker("name")
    role = FuzzyChoice(["user", "admin", "moderator"])
    
    @factory.post_generation
    def teams(self, create, extracted, **kwargs):
        """Add user to teams if specified."""
        if not create or not extracted:
            return
        
        for team in extracted:
            self.teams.append(team)
```

### Test Scenarios

```python
# tests/scenarios/chat_scenarios.py
"""Predefined test scenarios for chat functionality."""

CHAT_SCENARIOS = {
    "simple_greeting": {
        "messages": ["Hello!", "How are you?"],
        "expected_responses": 2,
        "min_response_length": 10
    },
    "technical_question": {
        "messages": [
            "How do I implement a binary search tree in Python?",
            "Can you show me an example?"
        ],
        "expected_responses": 2,
        "should_contain_code": True
    },
    "multi_turn_conversation": {
        "messages": [
            "I want to learn about machine learning",
            "What are neural networks?",
            "How do I get started with TensorFlow?",
            "Thanks for the help!"
        ],
        "expected_responses": 4,
        "should_maintain_context": True
    }
}
```

## Performance Testing

```python
# tests/performance/test_api_performance.py
"""Performance tests for API endpoints."""

import pytest
from locust import HttpUser, task, between

class APIUser(HttpUser):
    """Simulated API user for load testing."""
    
    wait_time = between(1, 3)
    
    def on_start(self):
        """Login before running tasks."""
        response = self.client.post("/api/v1/auth/login", json={
            "username": "testuser",
            "password": "testpass"
        })
        self.token = response.json()["token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}
    
    @task(3)
    def send_message(self):
        """Send a message (most common operation)."""
        self.client.post(
            "/api/v1/messages",
            headers=self.headers,
            json={
                "content": "Test message",
                "conversation_id": self.conversation_id
            }
        )
    
    @task(1)
    def get_history(self):
        """Get conversation history (less common)."""
        self.client.get(
            f"/api/v1/conversations/{self.conversation_id}",
            headers=self.headers
        )

# Run with: locust -f tests/performance/test_api_performance.py
```

## Test Coverage

### Coverage Configuration

```ini
# .coveragerc
[run]
source = src
omit = 
    */tests/*
    */migrations/*
    */__init__.py

[report]
precision = 2
show_missing = True
skip_covered = False

[html]
directory = htmlcov

[xml]
output = coverage.xml
```

### Running Coverage

```bash
# Run tests with coverage
pytest --cov=src --cov-report=html --cov-report=term

# Generate coverage badge
coverage-badge -o coverage.svg

# Check coverage threshold
pytest --cov=src --cov-fail-under=80
```