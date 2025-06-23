# Task 004: Knowledge Graph Unit Tests

## Priority: HIGH
**Estimated Time**: 4-5 hours  
**Dependencies**: Tasks 001-002 (Pytest setup, fixtures)  
**Blocking**: None

## Why This Task is Critical

The Knowledge Graph system integrates with vector stores and Apache AGE but has:
1. **No vector operation tests** - Embeddings might not work correctly
2. **No graph traversal tests** - Relationship queries untested
3. **No similarity search tests** - Core functionality unverified
4. **No chunk management tests** - Document processing could fail
5. **No performance tests** - Graph queries might be slow

## What Needs to Be Done

### 1. Knowledge Base Model Tests

Create `tests/unit/models/test_knowledge.py`:
```python
"""Unit tests for Knowledge models."""
import pytest
from datetime import datetime
from uuid import uuid4
import numpy as np
from src.infrastructure.database.models.knowledge import (
    KnowledgeBase, KnowledgeEntity, KnowledgeRelation, DocumentVector
)

class TestKnowledgeBase:
    """Test KnowledgeBase model."""
    
    def test_knowledge_base_creation(self):
        """Test creating knowledge base with valid data."""
        kb = KnowledgeBase(
            name="Company Knowledge",
            tenant_id=uuid4(),
            owner_id=uuid4(),
            vector_store="milvus",
            embedding_model="openai-ada-002"
        )
        assert kb.name == "Company Knowledge"
        assert kb.vector_store == "milvus"
        assert kb.statistics == {}
    
    @pytest.mark.parametrize("vector_store,valid", [
        ("milvus", True),
        ("chroma", True),
        ("invalid", False),
        (None, False),
    ])
    def test_vector_store_validation(self, vector_store, valid):
        """Test vector store type validation."""
        if valid:
            kb = KnowledgeBase(
                name="Test",
                vector_store=vector_store,
                tenant_id=uuid4(),
                owner_id=uuid4()
            )
            assert kb.vector_store == vector_store
        else:
            with pytest.raises(ValueError):
                KnowledgeBase(
                    name="Test",
                    vector_store=vector_store,
                    tenant_id=uuid4(),
                    owner_id=uuid4()
                )
    
    def test_embedding_dimension_validation(self):
        """Test embedding dimension constraints."""
        kb = KnowledgeBase(
            name="Test",
            tenant_id=uuid4(),
            owner_id=uuid4(),
            embedding_dimension=1536  # OpenAI dimension
        )
        assert kb.embedding_dimension == 1536
        
        # Test invalid dimensions
        with pytest.raises(ValueError):
            KnowledgeBase(
                name="Test",
                tenant_id=uuid4(),
                owner_id=uuid4(),
                embedding_dimension=0
            )
    
    def test_statistics_update(self):
        """Test updating knowledge base statistics."""
        kb = KnowledgeBase(
            name="Test",
            tenant_id=uuid4(),
            owner_id=uuid4()
        )
        
        kb.update_statistics({
            "total_entities": 100,
            "total_relations": 250,
            "total_vectors": 500
        })
        
        assert kb.statistics["total_entities"] == 100
        assert kb.total_entities == 100
        assert kb.total_vectors == 500
```

### 2. Knowledge Entity Tests

Create `tests/unit/models/test_knowledge_entity.py`:
```python
"""Unit tests for KnowledgeEntity model."""
import pytest
from uuid import uuid4
import json
from src.infrastructure.database.models.knowledge import KnowledgeEntity

class TestKnowledgeEntity:
    """Test knowledge entity functionality."""
    
    def test_entity_creation(self):
        """Test creating entity with valid data."""
        entity = KnowledgeEntity(
            knowledge_base_id=uuid4(),
            entity_type="person",
            name="John Doe",
            properties={
                "role": "CEO",
                "email": "john@example.com"
            }
        )
        assert entity.entity_type == "person"
        assert entity.name == "John Doe"
        assert entity.properties["role"] == "CEO"
    
    @pytest.mark.parametrize("entity_type", [
        "person", "organization", "location", "concept", "document"
    ])
    def test_valid_entity_types(self, entity_type):
        """Test valid entity types."""
        entity = KnowledgeEntity(
            knowledge_base_id=uuid4(),
            entity_type=entity_type,
            name="Test Entity"
        )
        assert entity.entity_type == entity_type
    
    def test_entity_extraction_metadata(self):
        """Test entity extraction with confidence scores."""
        entity = KnowledgeEntity(
            knowledge_base_id=uuid4(),
            entity_type="person",
            name="Jane Smith",
            source_document_id=uuid4(),
            extraction_metadata={
                "confidence": 0.95,
                "method": "ner",
                "model": "spacy-en"
            }
        )
        
        assert entity.extraction_metadata["confidence"] == 0.95
        assert entity.extraction_metadata["method"] == "ner"
    
    def test_entity_properties_validation(self):
        """Test entity properties are JSON serializable."""
        entity = KnowledgeEntity(
            knowledge_base_id=uuid4(),
            entity_type="organization",
            name="ACME Corp"
        )
        
        # Valid properties
        entity.properties = {
            "founded": "2020",
            "employees": 100,
            "public": True,
            "sectors": ["tech", "finance"]
        }
        
        # Should be JSON serializable
        json_str = json.dumps(entity.properties)
        assert json_str is not None
    
    def test_entity_deduplication_key(self):
        """Test entity deduplication."""
        entity1 = KnowledgeEntity(
            knowledge_base_id=uuid4(),
            entity_type="person",
            name="John Doe"
        )
        
        entity2 = KnowledgeEntity(
            knowledge_base_id=entity1.knowledge_base_id,
            entity_type="person",
            name="john doe"  # Different case
        )
        
        # Should generate same dedup key
        assert entity1.get_dedup_key() == entity2.get_dedup_key()
```

### 3. Knowledge Relation Tests

Create `tests/unit/repositories/test_knowledge_relation_repository.py`:
```python
"""Unit tests for KnowledgeRelation repository."""
import pytest
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4
from src.infrastructure.database.repositories.knowledge import KnowledgeRelationRepository
from src.infrastructure.database.models.knowledge import KnowledgeRelation

class TestKnowledgeRelationRepository:
    """Test knowledge relation operations."""
    
    @pytest.mark.asyncio
    async def test_create_relation(self, mock_session):
        """Test creating entity relation."""
        repo = KnowledgeRelationRepository(KnowledgeRelation, mock_session)
        
        source_id = uuid4()
        target_id = uuid4()
        
        relation = await repo.create_relation(
            knowledge_base_id=uuid4(),
            source_entity_id=source_id,
            target_entity_id=target_id,
            relation_type="works_for",
            properties={"since": "2020"}
        )
        
        assert relation is not None
        assert mock_session.add.called
        added_relation = mock_session.add.call_args[0][0]
        assert added_relation.relation_type == "works_for"
    
    @pytest.mark.asyncio
    async def test_find_paths_between_entities(self, mock_session):
        """Test finding paths between entities."""
        # This would test graph traversal
        repo = KnowledgeRelationRepository(KnowledgeRelation, mock_session)
        
        # Mock graph query result
        mock_paths = [
            {
                "path": ["entity1", "entity2", "entity3"],
                "relations": ["knows", "works_with"],
                "length": 2
            }
        ]
        
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = mock_paths
        mock_session.execute.return_value = mock_result
        
        paths = await repo.find_paths(
            source_id=uuid4(),
            target_id=uuid4(),
            max_depth=3
        )
        
        assert len(paths) == 1
        assert paths[0]["length"] == 2
    
    @pytest.mark.asyncio
    async def test_get_entity_neighbors(self, mock_session):
        """Test getting entity neighbors."""
        repo = KnowledgeRelationRepository(KnowledgeRelation, mock_session)
        
        # Mock related entities
        mock_neighbors = [
            MagicMock(id=uuid4(), name="Entity 1", relation_type="knows"),
            MagicMock(id=uuid4(), name="Entity 2", relation_type="works_with")
        ]
        
        mock_result = AsyncMock()
        mock_result.all.return_value = mock_neighbors
        mock_session.execute.return_value = mock_result
        
        neighbors = await repo.get_neighbors(
            entity_id=uuid4(),
            relation_types=["knows", "works_with"],
            depth=1
        )
        
        assert len(neighbors) == 2
    
    @pytest.mark.asyncio
    async def test_temporal_relations(self, mock_session):
        """Test temporal validity of relations."""
        repo = KnowledgeRelationRepository(KnowledgeRelation, mock_session)
        
        # Create relation with validity period
        relation = await repo.create_relation(
            knowledge_base_id=uuid4(),
            source_entity_id=uuid4(),
            target_entity_id=uuid4(),
            relation_type="employed_by",
            valid_from=datetime(2020, 1, 1),
            valid_to=datetime(2022, 12, 31)
        )
        
        # Test validity checking
        assert relation.is_valid_at(datetime(2021, 6, 15)) is True
        assert relation.is_valid_at(datetime(2023, 1, 1)) is False
```

### 4. Document Vector Tests

Create `tests/unit/models/test_document_vector.py`:
```python
"""Unit tests for DocumentVector model."""
import pytest
import numpy as np
from uuid import uuid4
from src.infrastructure.database.models.knowledge import DocumentVector

class TestDocumentVector:
    """Test document vector functionality."""
    
    def test_vector_creation(self):
        """Test creating document vector reference."""
        vector = DocumentVector(
            document_id=uuid4(),
            knowledge_base_id=uuid4(),
            chunk_index=0,
            chunk_text="This is a test chunk",
            vector_id="vec_123",
            embedding_model="openai-ada-002"
        )
        
        assert vector.chunk_index == 0
        assert vector.vector_id == "vec_123"
        assert len(vector.chunk_text) > 0
    
    def test_chunk_size_validation(self):
        """Test chunk size constraints."""
        # Test max chunk size
        long_text = "x" * 10000  # Too long
        
        with pytest.raises(ValueError):
            DocumentVector(
                document_id=uuid4(),
                knowledge_base_id=uuid4(),
                chunk_index=0,
                chunk_text=long_text,
                vector_id="vec_123"
            )
    
    def test_chunk_overlap_metadata(self):
        """Test chunk overlap handling."""
        vector = DocumentVector(
            document_id=uuid4(),
            knowledge_base_id=uuid4(),
            chunk_index=1,
            chunk_text="overlapping text here",
            metadata={
                "overlap_start": 50,
                "overlap_end": 100,
                "total_chunks": 10
            }
        )
        
        assert vector.metadata["overlap_start"] == 50
        assert vector.metadata["total_chunks"] == 10
    
    def test_vector_similarity_metadata(self):
        """Test storing similarity search metadata."""
        vector = DocumentVector(
            document_id=uuid4(),
            knowledge_base_id=uuid4(),
            chunk_index=0,
            chunk_text="test",
            vector_id="vec_123",
            metadata={
                "avg_similarity": 0.85,
                "max_similarity": 0.95,
                "search_count": 10
            }
        )
        
        assert vector.metadata["avg_similarity"] == 0.85
```

### 5. Vector Operations Mock Tests

Create `tests/unit/repositories/test_vector_operations.py`:
```python
"""Unit tests for vector operations."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import numpy as np
from uuid import uuid4

class TestVectorOperations:
    """Test vector store operations."""
    
    @pytest.mark.asyncio
    async def test_add_document_vectors(self):
        """Test adding document vectors to store."""
        # Mock vector store client
        mock_client = AsyncMock()
        mock_client.add_vectors.return_value = ["vec_1", "vec_2", "vec_3"]
        
        # Mock embedding function
        mock_embeddings = [
            np.random.rand(1536).tolist(),
            np.random.rand(1536).tolist(),
            np.random.rand(1536).tolist()
        ]
        
        with patch("src.services.vector_store.get_embeddings", return_value=mock_embeddings):
            vector_ids = await add_document_to_vector_store(
                document_id=uuid4(),
                chunks=["chunk1", "chunk2", "chunk3"],
                knowledge_base_id=uuid4()
            )
        
        assert len(vector_ids) == 3
        mock_client.add_vectors.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_similarity_search(self):
        """Test vector similarity search."""
        mock_client = AsyncMock()
        mock_results = [
            {"id": "vec_1", "score": 0.95, "metadata": {"chunk": "result1"}},
            {"id": "vec_2", "score": 0.87, "metadata": {"chunk": "result2"}}
        ]
        mock_client.search.return_value = mock_results
        
        results = await search_similar_vectors(
            query="test query",
            knowledge_base_id=uuid4(),
            top_k=10,
            threshold=0.8
        )
        
        assert len(results) == 2
        assert results[0]["score"] > results[1]["score"]  # Ordered by score
    
    @pytest.mark.asyncio
    async def test_vector_deletion(self):
        """Test removing vectors when document deleted."""
        mock_client = AsyncMock()
        mock_client.delete_vectors.return_value = True
        
        # Get vector IDs for document
        vector_ids = ["vec_1", "vec_2", "vec_3"]
        
        success = await delete_document_vectors(
            document_id=uuid4(),
            vector_ids=vector_ids
        )
        
        assert success is True
        mock_client.delete_vectors.assert_called_with(vector_ids)
    
    @pytest.mark.asyncio
    async def test_reindex_vectors(self):
        """Test reindexing vectors with new embeddings."""
        mock_client = AsyncMock()
        
        # Mock getting existing vectors
        mock_client.get_vectors.return_value = [
            {"id": "vec_1", "metadata": {"chunk": "text1"}},
            {"id": "vec_2", "metadata": {"chunk": "text2"}}
        ]
        
        # Mock new embeddings
        new_embeddings = [
            np.random.rand(1536).tolist(),
            np.random.rand(1536).tolist()
        ]
        
        with patch("src.services.vector_store.get_embeddings", return_value=new_embeddings):
            success = await reindex_document(
                document_id=uuid4(),
                new_model="openai-ada-003"
            )
        
        assert success is True
        assert mock_client.update_vectors.called
```

### 6. Knowledge Graph Query Tests

Create `tests/unit/repositories/test_knowledge_graph_queries.py`:
```python
"""Unit tests for knowledge graph queries."""
import pytest
from unittest.mock import AsyncMock
from uuid import uuid4

class TestKnowledgeGraphQueries:
    """Test complex graph queries."""
    
    @pytest.mark.asyncio
    async def test_find_related_documents(self, mock_session):
        """Test finding documents related to entity."""
        # Mock query that joins entities to documents
        mock_docs = [
            {"doc_id": uuid4(), "title": "Doc 1", "relevance": 0.9},
            {"doc_id": uuid4(), "title": "Doc 2", "relevance": 0.7}
        ]
        
        mock_result = AsyncMock()
        mock_result.all.return_value = mock_docs
        mock_session.execute.return_value = mock_result
        
        docs = await find_entity_documents(
            entity_id=uuid4(),
            relationship_types=["mentions", "describes"],
            min_relevance=0.5
        )
        
        assert len(docs) == 2
        assert docs[0]["relevance"] > docs[1]["relevance"]
    
    @pytest.mark.asyncio
    async def test_entity_clustering(self, mock_session):
        """Test finding entity clusters."""
        # Mock entities that are highly connected
        mock_clusters = [
            {
                "cluster_id": 1,
                "entities": [uuid4(), uuid4(), uuid4()],
                "density": 0.8
            }
        ]
        
        clusters = await find_entity_clusters(
            knowledge_base_id=uuid4(),
            min_cluster_size=3,
            min_density=0.7
        )
        
        assert len(clusters) == 1
        assert len(clusters[0]["entities"]) >= 3
    
    @pytest.mark.asyncio
    async def test_knowledge_graph_statistics(self, mock_session):
        """Test computing graph statistics."""
        stats = await compute_graph_statistics(
            knowledge_base_id=uuid4()
        )
        
        expected_stats = {
            "total_entities": 150,
            "total_relations": 450,
            "avg_degree": 3.0,
            "max_degree": 15,
            "connected_components": 5,
            "density": 0.02
        }
        
        for key, value in expected_stats.items():
            assert stats[key] == value
```

## Success Criteria

1. ✅ Knowledge base model validation is tested
2. ✅ Entity creation and deduplication is tested
3. ✅ Relation temporal validity is tested
4. ✅ Vector operations are mocked and tested
5. ✅ Graph traversal queries are tested
6. ✅ Similarity search functionality is tested
7. ✅ All tests use assertions, not print statements
8. ✅ Complex graph queries are tested with mocks

## Common Patterns to Test

1. **Vector Dimensions**: Ensure correct embedding sizes
2. **Entity Types**: Validate allowed entity types
3. **Relation Types**: Test bidirectional vs unidirectional
4. **Temporal Queries**: Past, present, future relations
5. **Graph Paths**: Shortest path, all paths, limited depth
6. **Vector Search**: Threshold filtering, top-k results
7. **Chunking**: Overlap, size limits, metadata

## Next Steps

After this task:
- Run tests: `pytest tests/unit/models/test_knowledge.py -v`
- Check coverage: `pytest tests/unit --cov=src.infrastructure.database.models.knowledge`
- Move on to Tool System unit tests (Task 005)
- Integrate with performance tests later (Task 008)

## Notes

- Mock all vector store operations
- Test both Milvus and Chroma code paths
- Use numpy for realistic vector data
- Test edge cases like empty graphs
- Verify metadata is properly stored