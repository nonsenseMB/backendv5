# Task 003: Document System Unit Tests

## Priority: HIGH
**Estimated Time**: 4-5 hours  
**Dependencies**: Tasks 001-002 (Pytest setup, fixtures)  
**Blocking**: None

## Why This Task is Critical

The Document System is core to the platform but currently has:
1. **No validation tests** - Invalid data could corrupt the database
2. **No permission tests** - Users might access unauthorized documents
3. **No edge case tests** - System behavior with nulls, empty strings unknown
4. **No version control tests** - Document history might be lost
5. **No collaboration tests** - Real-time features untested

## What Needs to Be Done

### 1. Document Model Unit Tests

Create `tests/unit/models/test_document.py`:
```python
"""Unit tests for Document model."""
import pytest
from datetime import datetime
from uuid import uuid4
from src.infrastructure.database.models.document import (
    Document, DocumentContent, DocumentPermission, DocumentShare
)

class TestDocumentModel:
    """Test Document model validation and methods."""
    
    def test_document_creation_valid(self):
        """Test creating document with valid data."""
        doc = Document(
            title="Test Document",
            tenant_id=uuid4(),
            owner_id=uuid4(),
            document_type="document",
            status="draft"
        )
        assert doc.title == "Test Document"
        assert doc.slug is None  # Should be generated on save
        assert doc.tags == []
        assert doc.metadata == {}
    
    @pytest.mark.parametrize("invalid_title", [
        None,
        "",
        " ",
        "a" * 256,  # Too long
        "\n\n\n",   # Only whitespace
    ])
    def test_document_invalid_title(self, invalid_title):
        """Test document creation with invalid titles."""
        with pytest.raises(ValueError):
            Document(
                title=invalid_title,
                tenant_id=uuid4(),
                owner_id=uuid4()
            )
    
    def test_document_slug_generation(self):
        """Test automatic slug generation."""
        doc = Document(title="My Test Document!")
        expected_slug = "my-test-document"
        assert doc.generate_slug() == expected_slug
    
    def test_document_slug_uniqueness(self):
        """Test slug uniqueness handling."""
        # This needs mock of existing slugs
        doc = Document(title="Test")
        existing_slugs = ["test", "test-1", "test-2"]
        unique_slug = doc.generate_unique_slug(existing_slugs)
        assert unique_slug == "test-3"
    
    def test_document_reading_time_calculation(self):
        """Test reading time estimation."""
        doc = Document()
        
        # Test with different content sizes
        assert doc.calculate_reading_time("") == 0
        assert doc.calculate_reading_time("word " * 200) == 1  # ~1 minute
        assert doc.calculate_reading_time("word " * 1000) == 5  # ~5 minutes
    
    @pytest.mark.parametrize("doc_type,expected", [
        ("document", True),
        ("template", True),
        ("unknown", False),
        (None, False),
    ])
    def test_document_type_validation(self, doc_type, expected):
        """Test document type validation."""
        if expected:
            doc = Document(
                title="Test",
                document_type=doc_type,
                tenant_id=uuid4(),
                owner_id=uuid4()
            )
            assert doc.document_type == doc_type
        else:
            with pytest.raises(ValueError):
                Document(
                    title="Test",
                    document_type=doc_type,
                    tenant_id=uuid4(),
                    owner_id=uuid4()
                )
```

### 2. Document Repository Unit Tests

Create `tests/unit/repositories/test_document_repository.py`:
```python
"""Unit tests for Document repository."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
from sqlalchemy import select
from src.infrastructure.database.repositories.document import DocumentRepository
from src.infrastructure.database.models.document import Document

class TestDocumentRepository:
    """Test DocumentRepository methods."""
    
    @pytest.fixture
    def mock_document(self):
        """Create mock document."""
        doc = MagicMock(spec=Document)
        doc.id = uuid4()
        doc.title = "Test Document"
        doc.tenant_id = uuid4()
        return doc
    
    @pytest.mark.asyncio
    async def test_get_by_slug_found(self, mock_session, mock_document):
        """Test getting document by slug when it exists."""
        # Arrange
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_document
        mock_session.execute.return_value = mock_result
        
        repo = DocumentRepository(Document, mock_session)
        
        # Act
        result = await repo.get_by_slug("test-doc", mock_document.tenant_id)
        
        # Assert
        assert result == mock_document
        mock_session.execute.assert_called_once()
        
        # Verify the query structure
        call_args = mock_session.execute.call_args[0][0]
        assert "WHERE" in str(call_args)
        assert "slug" in str(call_args)
    
    @pytest.mark.asyncio
    async def test_get_by_slug_not_found(self, mock_session):
        """Test getting document by slug when not found."""
        # Arrange
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result
        
        repo = DocumentRepository(Document, mock_session)
        
        # Act
        result = await repo.get_by_slug("non-existent", uuid4())
        
        # Assert
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_user_documents_filters(self, mock_session):
        """Test get_user_documents with various filters."""
        # Arrange
        mock_docs = [MagicMock(spec=Document) for _ in range(3)]
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = mock_docs
        mock_session.execute.return_value = mock_result
        
        repo = DocumentRepository(Document, mock_session)
        tenant_id = uuid4()
        user_id = uuid4()
        
        # Act
        result = await repo.get_user_documents(
            user_id=user_id,
            tenant_id=tenant_id,
            status="published",
            document_type="template"
        )
        
        # Assert
        assert len(result) == 3
        mock_session.execute.assert_called_once()
        
        # Verify filters were applied
        call_args = str(mock_session.execute.call_args[0][0])
        assert "status" in call_args
        assert "document_type" in call_args
    
    @pytest.mark.asyncio
    async def test_search_documents(self, mock_session):
        """Test document search functionality."""
        # Arrange
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute.return_value = mock_result
        
        repo = DocumentRepository(Document, mock_session)
        
        # Act
        result = await repo.search_documents(
            tenant_id=uuid4(),
            query="test query",
            filters={"type": "document", "status": "published"}
        )
        
        # Assert
        assert result == []
        call_args = str(mock_session.execute.call_args[0][0])
        assert "ILIKE" in call_args or "ilike" in call_args
    
    @pytest.mark.asyncio
    async def test_increment_view_count(self, mock_session, mock_document):
        """Test incrementing document view count."""
        # Arrange
        repo = DocumentRepository(Document, mock_session)
        mock_session.execute = AsyncMock()
        
        # Act
        await repo.increment_view_count(mock_document.id)
        
        # Assert
        mock_session.execute.assert_called()
        mock_session.commit.assert_called_once()
```

### 3. Document Content Repository Tests

Create `tests/unit/repositories/test_document_content_repository.py`:
```python
"""Unit tests for DocumentContent repository."""
import pytest
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4
from src.infrastructure.database.repositories.document import DocumentContentRepository
from src.infrastructure.database.models.document import DocumentContent

class TestDocumentContentRepository:
    """Test DocumentContentRepository methods."""
    
    @pytest.mark.asyncio
    async def test_create_new_version(self, mock_session):
        """Test creating new document version."""
        # Arrange
        mock_result = AsyncMock()
        mock_result.scalar.return_value = 2  # Latest version
        mock_session.execute.return_value = mock_result
        
        repo = DocumentContentRepository(DocumentContent, mock_session)
        doc_id = uuid4()
        user_id = uuid4()
        
        # Act
        content = await repo.create_new_version(
            document_id=doc_id,
            user_id=user_id,
            content={"type": "doc", "content": []},
            change_description="Updated content"
        )
        
        # Assert
        assert content is not None
        assert mock_session.add.called
        assert mock_session.flush.called
        
        # Verify version was incremented
        added_content = mock_session.add.call_args[0][0]
        assert added_content.version == 3
        assert added_content.is_current == True
    
    @pytest.mark.asyncio
    async def test_get_version_history(self, mock_session):
        """Test retrieving version history."""
        # Arrange
        mock_versions = [
            MagicMock(version=3, created_at="2024-01-03"),
            MagicMock(version=2, created_at="2024-01-02"),
            MagicMock(version=1, created_at="2024-01-01"),
        ]
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = mock_versions
        mock_session.execute.return_value = mock_result
        
        repo = DocumentContentRepository(DocumentContent, mock_session)
        
        # Act
        history = await repo.get_version_history(uuid4())
        
        # Assert
        assert len(history) == 3
        assert history[0].version == 3  # Most recent first
    
    @pytest.mark.asyncio
    async def test_restore_version(self, mock_session):
        """Test restoring previous document version."""
        # Arrange
        old_version = MagicMock(
            version=2,
            content={"old": "content"},
            document_id=uuid4()
        )
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = old_version
        mock_session.execute.return_value = mock_result
        
        repo = DocumentContentRepository(DocumentContent, mock_session)
        
        # Act
        restored = await repo.restore_version(
            document_id=old_version.document_id,
            version=2,
            user_id=uuid4()
        )
        
        # Assert
        assert restored is not None
        assert mock_session.add.called
        restored_content = mock_session.add.call_args[0][0]
        assert restored_content.content == {"old": "content"}
        assert restored_content.change_description == "Restored from version 2"
```

### 4. Document Permission Tests

Create `tests/unit/repositories/test_document_permission_repository.py`:
```python
"""Unit tests for DocumentPermission repository."""
import pytest
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4
from src.infrastructure.database.repositories.document import DocumentPermissionRepository
from src.infrastructure.database.models.document import DocumentPermission

class TestDocumentPermissionRepository:
    """Test permission management."""
    
    @pytest.mark.asyncio
    async def test_check_permission_granted(self, mock_session):
        """Test checking permission when granted."""
        # Arrange
        mock_permission = MagicMock(permission="read")
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_permission
        mock_session.execute.return_value = mock_result
        
        repo = DocumentPermissionRepository(DocumentPermission, mock_session)
        
        # Act
        has_permission = await repo.check_permission(
            document_id=uuid4(),
            user_id=uuid4(),
            permission="read"
        )
        
        # Assert
        assert has_permission is True
    
    @pytest.mark.asyncio
    async def test_check_permission_denied(self, mock_session):
        """Test checking permission when not granted."""
        # Arrange
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result
        
        repo = DocumentPermissionRepository(DocumentPermission, mock_session)
        
        # Act
        has_permission = await repo.check_permission(
            document_id=uuid4(),
            user_id=uuid4(),
            permission="write"
        )
        
        # Assert
        assert has_permission is False
    
    @pytest.mark.asyncio
    async def test_grant_permission_new(self, mock_session):
        """Test granting new permission."""
        # Arrange
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = None  # No existing
        mock_session.execute.return_value = mock_result
        
        repo = DocumentPermissionRepository(DocumentPermission, mock_session)
        
        # Act
        permission = await repo.grant_permission(
            document_id=uuid4(),
            user_id=uuid4(),
            permission="write",
            granted_by_id=uuid4()
        )
        
        # Assert
        assert permission is not None
        assert mock_session.add.called
        added_perm = mock_session.add.call_args[0][0]
        assert added_perm.permission == "write"
    
    @pytest.mark.asyncio
    async def test_revoke_permission(self, mock_session):
        """Test revoking permission."""
        # Arrange
        mock_permission = MagicMock()
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_permission
        mock_session.execute.return_value = mock_result
        
        repo = DocumentPermissionRepository(DocumentPermission, mock_session)
        
        # Act
        result = await repo.revoke_permission(
            document_id=uuid4(),
            user_id=uuid4(),
            permission="write"
        )
        
        # Assert
        assert result is True
        mock_session.delete.assert_called_with(mock_permission)
```

### 5. Document Share Tests

Create `tests/unit/models/test_document_share.py`:
```python
"""Unit tests for document sharing."""
import pytest
from datetime import datetime, timedelta
from uuid import uuid4
from src.infrastructure.database.models.document import DocumentShare

class TestDocumentShare:
    """Test document sharing functionality."""
    
    def test_share_token_generation(self):
        """Test generating unique share tokens."""
        share = DocumentShare(
            document_id=uuid4(),
            created_by_id=uuid4()
        )
        
        token1 = share.generate_token()
        token2 = share.generate_token()
        
        assert len(token1) >= 32
        assert token1 != token2  # Should be unique
    
    def test_share_expiration(self):
        """Test share link expiration."""
        share = DocumentShare(
            document_id=uuid4(),
            created_by_id=uuid4(),
            expires_at=datetime.utcnow() - timedelta(hours=1)
        )
        
        assert share.is_expired() is True
        
        share.expires_at = datetime.utcnow() + timedelta(hours=1)
        assert share.is_expired() is False
    
    def test_share_password_protection(self):
        """Test password-protected shares."""
        share = DocumentShare(
            document_id=uuid4(),
            created_by_id=uuid4(),
            requires_password=True
        )
        
        # Set password
        share.set_password("secret123")
        assert share.password_hash is not None
        assert share.password_hash != "secret123"  # Should be hashed
        
        # Verify password
        assert share.verify_password("secret123") is True
        assert share.verify_password("wrong") is False
    
    def test_share_access_tracking(self):
        """Test tracking share access."""
        share = DocumentShare(
            document_id=uuid4(),
            created_by_id=uuid4(),
            max_uses=5
        )
        
        assert share.use_count == 0
        assert share.can_access() is True
        
        # Simulate uses
        for i in range(5):
            share.record_access()
            
        assert share.use_count == 5
        assert share.can_access() is False  # Max uses reached
```

## Success Criteria

1. ✅ All document models have validation tests
2. ✅ Repository methods are tested with mocks
3. ✅ Edge cases are covered (nulls, empty values, boundaries)
4. ✅ Permission system is thoroughly tested
5. ✅ Version control functionality is tested
6. ✅ Share functionality including passwords and expiration
7. ✅ All tests use proper assertions, not print statements
8. ✅ Tests are fast (< 1 second each) due to mocking

## Common Patterns to Test

1. **Validation**: Invalid inputs should raise appropriate errors
2. **Boundaries**: Test min/max values, empty strings, nulls
3. **Permissions**: Both granted and denied scenarios
4. **State Changes**: Draft -> Published, Current -> Historical
5. **Relationships**: Owner, permissions, content versions
6. **Concurrency**: Version conflicts, simultaneous edits
7. **Search**: Case sensitivity, partial matches, special characters

## Next Steps

After this task:
- Run tests with: `pytest tests/unit/models/test_document.py -v`
- Check coverage: `pytest tests/unit/models/test_document.py --cov=src.infrastructure.database.models.document`
- Move on to Knowledge Graph unit tests (Task 004)
- Later integrate with security tests (Task 006)

## Notes

- Mock all database calls in unit tests
- Use parametrize for testing multiple similar cases
- Keep tests focused on single functionality
- Name tests to describe what they verify
- Use factories from Task 002 for test data