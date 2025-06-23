# Task 007: Error Handling Tests

## Priority: HIGH
**Estimated Time**: 4-5 hours  
**Dependencies**: Tasks 001-002 (Pytest setup, fixtures)  
**Blocking**: Production stability

## Why This Task is Critical

Poor error handling causes:
1. **System crashes** - Unhandled exceptions bring down services
2. **Data corruption** - Partial operations without rollback
3. **Poor user experience** - Cryptic error messages
4. **Security leaks** - Stack traces exposing system internals
5. **Debugging nightmares** - No context when failures occur

## What Needs to Be Done

### 1. Database Error Handling Tests

Create `tests/unit/test_database_errors.py`:
```python
"""Test database error handling."""
import pytest
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4
from sqlalchemy.exc import (
    IntegrityError, OperationalError, DataError,
    DatabaseError, InvalidRequestError
)
from asyncpg.exceptions import UniqueViolationError
from src.infrastructure.database.repositories.document import DocumentRepository

class TestDatabaseErrors:
    """Test handling of database errors."""
    
    @pytest.mark.asyncio
    async def test_unique_constraint_violation(self, mock_session):
        """Test handling duplicate key errors."""
        # Mock unique violation
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock(
            side_effect=IntegrityError(
                "duplicate key",
                None,
                UniqueViolationError("duplicate key value")
            )
        )
        
        repo = DocumentRepository(Document, mock_session)
        
        # Should handle gracefully
        with pytest.raises(DuplicateResourceError) as exc_info:
            await repo.create(
                title="Duplicate Doc",
                slug="existing-slug",
                tenant_id=uuid4()
            )
        
        error = exc_info.value
        assert "already exists" in str(error)
        assert "slug" in str(error)  # Should identify the field
        assert error.field == "slug"
        assert error.value == "existing-slug"
    
    @pytest.mark.asyncio
    async def test_foreign_key_violation(self, mock_session):
        """Test handling foreign key constraint errors."""
        mock_session.flush = AsyncMock(
            side_effect=IntegrityError(
                "foreign key violation",
                None,
                None
            )
        )
        
        repo = DocumentRepository(Document, mock_session)
        
        with pytest.raises(InvalidReferenceError) as exc_info:
            await repo.create(
                title="Test",
                owner_id=uuid4(),  # Non-existent user
                tenant_id=uuid4()
            )
        
        error = exc_info.value
        assert "does not exist" in str(error)
        assert error.reference_type == "User"
    
    @pytest.mark.asyncio
    async def test_connection_failure(self, mock_session):
        """Test handling database connection failures."""
        mock_session.execute = AsyncMock(
            side_effect=OperationalError(
                "connection failed",
                None,
                None
            )
        )
        
        repo = DocumentRepository(Document, mock_session)
        
        with pytest.raises(DatabaseConnectionError) as exc_info:
            await repo.get(uuid4())
        
        error = exc_info.value
        assert "database connection" in str(error).lower()
        assert error.retry_after is not None  # Should suggest retry
    
    @pytest.mark.asyncio
    async def test_data_type_error(self, mock_session):
        """Test handling invalid data type errors."""
        mock_session.flush = AsyncMock(
            side_effect=DataError(
                "invalid input syntax",
                None,
                None
            )
        )
        
        repo = DocumentRepository(Document, mock_session)
        
        with pytest.raises(ValidationError) as exc_info:
            await repo.create(
                title="Test",
                metadata="not-a-dict",  # Should be dict
                tenant_id=uuid4()
            )
        
        error = exc_info.value
        assert "invalid data type" in str(error).lower()
        assert error.field == "metadata"
    
    @pytest.mark.asyncio
    async def test_transaction_rollback(self, mock_session):
        """Test transaction rollback on errors."""
        # Track rollback calls
        mock_session.rollback = AsyncMock()
        mock_session.flush = AsyncMock(
            side_effect=DatabaseError("error", None, None)
        )
        
        repo = DocumentRepository(Document, mock_session)
        
        with pytest.raises(DatabaseError):
            await repo.create(title="Test", tenant_id=uuid4())
        
        # Should have rolled back
        mock_session.rollback.assert_called_once()
```

### 2. Validation Error Tests

Create `tests/unit/test_validation_errors.py`:
```python
"""Test validation error handling."""
import pytest
from pydantic import ValidationError
from datetime import datetime
from uuid import uuid4
from src.api.schemas.document import DocumentCreate

class TestValidationErrors:
    """Test input validation error handling."""
    
    def test_missing_required_fields(self):
        """Test handling missing required fields."""
        with pytest.raises(ValidationError) as exc_info:
            DocumentCreate()  # Missing all required fields
        
        errors = exc_info.value.errors()
        assert len(errors) >= 2  # At least title and tenant_id
        
        # Check error details
        error_fields = [e["loc"][0] for e in errors]
        assert "title" in error_fields
        assert "tenant_id" in error_fields
        
        # Error messages should be helpful
        for error in errors:
            assert error["msg"] is not None
            assert "required" in error["msg"].lower()
    
    def test_invalid_field_types(self):
        """Test handling wrong field types."""
        with pytest.raises(ValidationError) as exc_info:
            DocumentCreate(
                title=123,  # Should be string
                tenant_id="not-a-uuid",  # Should be UUID
                tags="not-a-list",  # Should be list
                metadata=["not", "a", "dict"]  # Should be dict
            )
        
        errors = exc_info.value.errors()
        error_dict = {e["loc"][0]: e for e in errors}
        
        # Check each field error
        assert "title" in error_dict
        assert "string" in error_dict["title"]["msg"].lower()
        
        assert "tenant_id" in error_dict
        assert "uuid" in error_dict["tenant_id"]["msg"].lower()
    
    def test_field_constraints(self):
        """Test field constraint violations."""
        test_cases = [
            # (field, value, expected_error)
            ("title", "", "at least 1 character"),
            ("title", "x" * 256, "at most 255 characters"),
            ("tags", ["tag"] * 51, "at most 50 items"),
            ("content", {"invalid": "format"}, "content format"),
        ]
        
        for field, value, expected_error in test_cases:
            with pytest.raises(ValidationError) as exc_info:
                DocumentCreate(
                    title="Test" if field != "title" else value,
                    tenant_id=uuid4(),
                    **{field: value} if field != "title" else {}
                )
            
            errors = exc_info.value.errors()
            field_errors = [e for e in errors if field in e["loc"]]
            assert len(field_errors) > 0
            assert any(expected_error in e["msg"].lower() for e in field_errors)
    
    def test_custom_validators(self):
        """Test custom validation logic."""
        # Test slug validation
        with pytest.raises(ValidationError) as exc_info:
            DocumentCreate(
                title="Test",
                slug="Invalid Slug!",  # No spaces or special chars
                tenant_id=uuid4()
            )
        
        errors = exc_info.value.errors()
        slug_errors = [e for e in errors if "slug" in e["loc"]]
        assert len(slug_errors) > 0
        assert "alphanumeric" in slug_errors[0]["msg"].lower()
```

### 3. Business Logic Error Tests

Create `tests/unit/test_business_logic_errors.py`:
```python
"""Test business logic error handling."""
import pytest
from datetime import datetime, timedelta
from uuid import uuid4
from src.domain.exceptions import (
    BusinessRuleViolation, InvalidStateTransition,
    QuotaExceeded, ResourceLocked
)

class TestBusinessLogicErrors:
    """Test domain-specific error handling."""
    
    @pytest.mark.asyncio
    async def test_invalid_state_transition(self, mock_session):
        """Test handling invalid state transitions."""
        # Document in archived state
        doc = MagicMock(
            status="archived",
            can_transition_to=lambda s: s == "deleted"
        )
        
        repo = DocumentRepository(Document, mock_session)
        
        with pytest.raises(InvalidStateTransition) as exc_info:
            await repo.update_status(
                document=doc,
                new_status="published"  # Can't publish archived
            )
        
        error = exc_info.value
        assert error.current_state == "archived"
        assert error.requested_state == "published"
        assert error.allowed_states == ["deleted"]
    
    @pytest.mark.asyncio
    async def test_quota_exceeded(self, mock_session):
        """Test handling quota limits."""
        # Mock tenant at document limit
        mock_tenant = MagicMock(
            document_quota=100,
            document_count=100
        )
        
        with pytest.raises(QuotaExceeded) as exc_info:
            await create_document_with_quota_check(
                tenant=mock_tenant,
                title="One too many"
            )
        
        error = exc_info.value
        assert error.resource_type == "document"
        assert error.current_usage == 100
        assert error.quota_limit == 100
        assert error.upgrade_required is True
    
    @pytest.mark.asyncio
    async def test_resource_locked(self, mock_session):
        """Test handling locked resources."""
        doc = MagicMock(
            id=uuid4(),
            is_locked=True,
            locked_by_id=uuid4(),
            locked_until=datetime.utcnow() + timedelta(minutes=5)
        )
        
        current_user_id = uuid4()  # Different user
        
        with pytest.raises(ResourceLocked) as exc_info:
            await edit_document_with_lock_check(
                document=doc,
                user_id=current_user_id
            )
        
        error = exc_info.value
        assert error.resource_type == "document"
        assert error.locked_by != current_user_id
        assert error.locked_until > datetime.utcnow()
    
    @pytest.mark.asyncio
    async def test_business_rule_violation(self, mock_session):
        """Test general business rule violations."""
        # Try to share document that's not published
        doc = MagicMock(status="draft")
        
        with pytest.raises(BusinessRuleViolation) as exc_info:
            await create_public_share(document=doc)
        
        error = exc_info.value
        assert "must be published" in str(error)
        assert error.rule_name == "document_sharing"
        assert error.context["status"] == "draft"
```

### 4. Concurrent Operation Error Tests

Create `tests/unit/test_concurrency_errors.py`:
```python
"""Test concurrent operation error handling."""
import pytest
from datetime import datetime
from uuid import uuid4
from src.domain.exceptions import (
    OptimisticLockError, DeadlockError,
    ConcurrentModificationError
)

class TestConcurrencyErrors:
    """Test handling concurrent operation errors."""
    
    @pytest.mark.asyncio
    async def test_optimistic_lock_failure(self, mock_session):
        """Test handling version conflicts."""
        # Document with version
        doc = MagicMock(
            id=uuid4(),
            version=5,
            updated_at=datetime.utcnow()
        )
        
        # Simulate concurrent update (version changed)
        mock_session.execute = AsyncMock(
            return_value=MagicMock(rowcount=0)  # No rows updated
        )
        
        with pytest.raises(OptimisticLockError) as exc_info:
            await update_with_version_check(
                document=doc,
                updates={"title": "New Title"},
                expected_version=5
            )
        
        error = exc_info.value
        assert error.resource_type == "document"
        assert error.expected_version == 5
        assert "modified by another user" in str(error)
    
    @pytest.mark.asyncio
    async def test_deadlock_retry(self, mock_session):
        """Test deadlock detection and retry logic."""
        call_count = 0
        
        async def mock_execute(*args):
            nonlocal call_count
            call_count += 1
            if call_count < 3:  # Fail first 2 times
                raise OperationalError(
                    "deadlock detected",
                    None,
                    None
                )
            return MagicMock()  # Succeed on 3rd try
        
        mock_session.execute = mock_execute
        
        # Should retry and eventually succeed
        result = await execute_with_deadlock_retry(
            mock_session,
            max_retries=3
        )
        
        assert result is not None
        assert call_count == 3
    
    @pytest.mark.asyncio
    async def test_concurrent_modification(self, mock_session):
        """Test handling simultaneous modifications."""
        doc_id = uuid4()
        
        # Two users trying to edit same document
        with pytest.raises(ConcurrentModificationError) as exc_info:
            await handle_concurrent_edit(
                document_id=doc_id,
                user1_changes={"title": "User 1 Title"},
                user2_changes={"title": "User 2 Title"},
                strategy="fail"  # Don't merge
            )
        
        error = exc_info.value
        assert error.conflicts == ["title"]
        assert error.resolution_options == ["merge", "overwrite", "cancel"]
```

### 5. External Service Error Tests

Create `tests/unit/test_external_service_errors.py`:
```python
"""Test external service error handling."""
import pytest
from unittest.mock import patch, AsyncMock
import httpx
from src.services.exceptions import (
    ExternalServiceError, ServiceTimeout,
    RateLimitExceeded, ServiceUnavailable
)

class TestExternalServiceErrors:
    """Test handling external service failures."""
    
    @pytest.mark.asyncio
    async def test_mcp_connection_failure(self):
        """Test MCP server connection failures."""
        with patch("mcp_client.connect") as mock_connect:
            mock_connect.side_effect = ConnectionError("Connection refused")
            
            with pytest.raises(ExternalServiceError) as exc_info:
                await connect_to_mcp_server(
                    server_url="http://localhost:8080"
                )
            
            error = exc_info.value
            assert error.service_name == "mcp_server"
            assert error.retry_available is True
            assert error.fallback_available is False
    
    @pytest.mark.asyncio
    async def test_vector_store_timeout(self):
        """Test vector store operation timeouts."""
        with patch("vector_store.search") as mock_search:
            mock_search.side_effect = asyncio.TimeoutError()
            
            with pytest.raises(ServiceTimeout) as exc_info:
                await search_vectors(
                    query="test",
                    timeout=5.0
                )
            
            error = exc_info.value
            assert error.service_name == "vector_store"
            assert error.timeout_seconds == 5.0
            assert error.operation == "search"
    
    @pytest.mark.asyncio
    async def test_api_rate_limit(self):
        """Test handling API rate limit errors."""
        mock_response = httpx.Response(
            status_code=429,
            headers={
                "X-RateLimit-Limit": "100",
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": "1640995200"
            }
        )
        
        with patch("httpx.AsyncClient.post") as mock_post:
            mock_post.return_value = mock_response
            
            with pytest.raises(RateLimitExceeded) as exc_info:
                await call_external_api()
            
            error = exc_info.value
            assert error.limit == 100
            assert error.reset_time is not None
            assert error.retry_after > 0
    
    @pytest.mark.asyncio
    async def test_service_degradation(self):
        """Test graceful degradation when services fail."""
        # Mock multiple service failures
        with patch("vector_store.available", return_value=False):
            with patch("knowledge_graph.available", return_value=False):
                
                # Should fall back to basic search
                results = await search_with_fallback(
                    query="test",
                    use_vectors=True,
                    use_graph=True
                )
                
                assert results is not None
                assert results["fallback_used"] is True
                assert results["degraded_features"] == ["vectors", "graph"]
```

### 6. Error Recovery Tests

Create `tests/unit/test_error_recovery.py`:
```python
"""Test error recovery mechanisms."""
import pytest
from datetime import datetime, timedelta

class TestErrorRecovery:
    """Test system recovery from errors."""
    
    @pytest.mark.asyncio
    async def test_circuit_breaker(self):
        """Test circuit breaker pattern."""
        breaker = CircuitBreaker(
            failure_threshold=3,
            timeout=timedelta(seconds=30)
        )
        
        # Simulate failures
        for i in range(3):
            with pytest.raises(ExternalServiceError):
                await breaker.call(failing_service)
        
        # Circuit should be open
        assert breaker.state == "open"
        
        # Further calls should fail fast
        with pytest.raises(CircuitBreakerOpen):
            await breaker.call(failing_service)
        
        # After timeout, should try again
        breaker._last_failure = datetime.utcnow() - timedelta(seconds=31)
        assert breaker.state == "half-open"
    
    @pytest.mark.asyncio
    async def test_automatic_retry_with_backoff(self):
        """Test exponential backoff retry."""
        attempt_times = []
        
        @retry_with_backoff(max_attempts=3, base_delay=1.0)
        async def flaky_operation():
            attempt_times.append(datetime.utcnow())
            if len(attempt_times) < 3:
                raise TemporaryError("Try again")
            return "Success"
        
        result = await flaky_operation()
        assert result == "Success"
        assert len(attempt_times) == 3
        
        # Check exponential delays
        delay1 = (attempt_times[1] - attempt_times[0]).total_seconds()
        delay2 = (attempt_times[2] - attempt_times[1]).total_seconds()
        assert delay2 > delay1  # Exponential increase
    
    @pytest.mark.asyncio
    async def test_compensating_transaction(self):
        """Test rollback of partial operations."""
        operations_performed = []
        
        async def operation_sequence():
            try:
                # Step 1: Create document
                doc = await create_document()
                operations_performed.append(("create_doc", doc.id))
                
                # Step 2: Add to vector store
                vector_id = await add_to_vectors(doc)
                operations_performed.append(("add_vector", vector_id))
                
                # Step 3: Update graph (this fails)
                raise GraphUpdateError("Graph unavailable")
                
            except Exception as e:
                # Compensate in reverse order
                await compensate_operations(operations_performed)
                raise
        
        with pytest.raises(GraphUpdateError):
            await operation_sequence()
        
        # Verify compensation occurred
        assert not await document_exists(operations_performed[0][1])
        assert not await vector_exists(operations_performed[1][1])
```

## Success Criteria

1. ✅ All database errors are caught and wrapped
2. ✅ Validation errors provide clear messages
3. ✅ Business logic violations are explicit
4. ✅ Concurrent operations handle conflicts
5. ✅ External service failures are handled
6. ✅ Recovery mechanisms work correctly
7. ✅ No sensitive data in error messages
8. ✅ All errors are properly logged

## Error Handling Checklist

- [ ] Database connection failures
- [ ] Constraint violations (unique, foreign key, check)
- [ ] Transaction deadlocks
- [ ] Validation errors with field details
- [ ] Business rule violations
- [ ] State transition errors
- [ ] Quota/limit exceeded
- [ ] Concurrent modification conflicts
- [ ] External service timeouts
- [ ] Rate limiting
- [ ] Circuit breaker functionality
- [ ] Retry with backoff
- [ ] Compensating transactions
- [ ] Graceful degradation
- [ ] Error message sanitization

## Next Steps

After this task:
- Run tests: `pytest tests/unit/test_*_errors.py -v`
- Check error handling coverage
- Review error messages for clarity
- Move on to Concurrency tests (Task 008)

## Notes

- Always test both the error case and recovery
- Ensure errors contain enough context for debugging
- Never expose system internals in errors
- Test that transactions roll back properly
- Verify error logging includes correlation IDs