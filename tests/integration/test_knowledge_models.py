"""
Integration tests for Knowledge Graph models.
Tests vector storage integration, entity relationships, and Apache AGE compatibility.
"""
import asyncio
from datetime import datetime
from uuid import uuid4

from src.infrastructure.database.session import get_async_session, init_db
from src.infrastructure.database.unit_of_work import UnitOfWork


async def test_knowledge_graph_integration():
    """Test complete Knowledge Graph integration."""
    print("🧠 Testing Knowledge Graph Integration...")
    
    await init_db()
    
    async for session in get_async_session():
        async with UnitOfWork(session) as uow:
            # Setup: Create tenant and user
            print("\n1. Setting up test data...")
            tenant = await uow.tenants.create(
                name="Knowledge Test Corp",
                slug="knowledge-test",
                plan_type="enterprise",
                is_active=True
            )
            
            user = await uow.users.create(
                external_id="knowledge_test_123",
                email="knowledge@example.com",
                username="knowledge_user",
                full_name="Knowledge Test User",
                is_active=True
            )
            
            print(f"   Created tenant: {tenant.name}")
            print(f"   Created user: {user.email}")
            
            # Test KnowledgeBase CRUD
            print("\n2. Testing KnowledgeBase CRUD...")
            tenant_uow = uow.with_tenant(tenant.id)
            
            kb = await tenant_uow.knowledge_bases.create(
                name="test_knowledge_base",
                display_name="Test Knowledge Base",
                description="A knowledge base for testing",
                vector_store_type="milvus",
                collection_name="test_collection_v1",
                embedding_model="text-embedding-ada-002",
                embedding_dimension=1536,
                graph_name="test_graph",
                enable_graph_queries=True,
                owner_id=user.id,
                chunk_size=1000,
                chunk_overlap=100
            )
            
            print(f"   Created knowledge base: {kb.display_name}")
            assert kb.vector_store_type == "milvus"
            assert kb.embedding_dimension == 1536
            assert kb.enable_graph_queries == True
            
            # Test get by name and collection
            kb_by_name = await tenant_uow.knowledge_bases.get_by_name(kb.name, tenant.id)
            assert kb_by_name.id == kb.id
            
            kb_by_collection = await uow.knowledge_bases.get_by_collection(kb.collection_name)
            assert kb_by_collection.id == kb.id
            print(f"   Retrieved KB by name and collection")
            
            # Test KnowledgeEntity CRUD
            print("\n3. Testing KnowledgeEntity CRUD...")
            
            # Create entities
            entities = []
            entity_data = [
                {
                    "entity_id": "person_john_doe",
                    "entity_type": "person",
                    "name": "John Doe",
                    "canonical_name": "john_doe",
                    "properties": {"title": "Software Engineer", "company": "TechCorp"},
                    "aliases": ["Johnny", "J. Doe"],
                    "description": "Senior software engineer at TechCorp",
                    "confidence_score": 0.95,
                    "extraction_method": "ner"
                },
                {
                    "entity_id": "org_techcorp",
                    "entity_type": "organization",
                    "name": "TechCorp",
                    "canonical_name": "techcorp",
                    "properties": {"industry": "Technology", "founded": "2010"},
                    "aliases": ["Tech Corporation", "TC"],
                    "description": "A technology company",
                    "confidence_score": 0.98,
                    "extraction_method": "manual"
                },
                {
                    "entity_id": "concept_ai",
                    "entity_type": "concept",
                    "name": "Artificial Intelligence",
                    "canonical_name": "artificial_intelligence",
                    "properties": {"field": "Computer Science", "subfield": "Machine Learning"},
                    "aliases": ["AI", "Machine Intelligence"],
                    "description": "Field of computer science focused on creating intelligent machines",
                    "confidence_score": 1.0,
                    "extraction_method": "import"
                }
            ]
            
            for data in entity_data:
                entity = await uow.knowledge_entities.create(
                    knowledge_base_id=kb.id,
                    **data
                )
                entities.append(entity)
                print(f"   Created entity: {entity.name} ({entity.entity_type})")
            
            # Test entity search
            print("\n4. Testing entity search and retrieval...")
            
            # Search by name
            search_results = await uow.knowledge_entities.search_entities(
                knowledge_base_id=kb.id,
                query="John",
                limit=10
            )
            assert len(search_results) == 1
            assert search_results[0].name == "John Doe"
            print(f"   Found {len(search_results)} entities matching 'John'")
            
            # Get entities by type
            people = await uow.knowledge_entities.get_entities_by_type(
                knowledge_base_id=kb.id,
                entity_type="person"
            )
            assert len(people) == 1
            print(f"   Found {len(people)} person entities")
            
            # Get by entity_id
            john = await uow.knowledge_entities.get_by_entity_id(
                "person_john_doe",
                kb.id
            )
            assert john.name == "John Doe"
            print(f"   Retrieved entity by ID: {john.name}")
            
            # Test KnowledgeRelation CRUD
            print("\n5. Testing KnowledgeRelation CRUD...")
            
            # Create relationships
            relations = []
            relation_data = [
                {
                    "relation_id": "rel_john_works_at_techcorp",
                    "relation_type": "works_at",
                    "source_entity_id": entities[0].id,  # John
                    "target_entity_id": entities[1].id,  # TechCorp
                    "properties": {"start_date": "2020-01-01", "position": "Senior Engineer"},
                    "weight": 0.9,
                    "confidence_score": 0.95,
                    "extraction_method": "pattern"
                },
                {
                    "relation_id": "rel_john_specializes_ai",
                    "relation_type": "specializes_in",
                    "source_entity_id": entities[0].id,  # John
                    "target_entity_id": entities[2].id,  # AI
                    "properties": {"years_experience": "5", "level": "expert"},
                    "weight": 0.8,
                    "confidence_score": 0.85,
                    "extraction_method": "llm"
                },
                {
                    "relation_id": "rel_techcorp_develops_ai",
                    "relation_type": "develops",
                    "source_entity_id": entities[1].id,  # TechCorp
                    "target_entity_id": entities[2].id,  # AI
                    "properties": {"focus_area": "NLP", "investment": "high"},
                    "weight": 0.85,
                    "confidence_score": 0.9,
                    "extraction_method": "manual"
                }
            ]
            
            for data in relation_data:
                relation = await uow.knowledge_relations.create(
                    knowledge_base_id=kb.id,
                    **data
                )
                relations.append(relation)
                print(f"   Created relation: {relation.relation_type} (confidence: {relation.confidence_score})")
            
            # Test relationship queries
            print("\n6. Testing relationship queries...")
            
            # Get entity relations
            john_relations = await uow.knowledge_relations.get_entity_relations(
                entity_id=entities[0].id,  # John
                direction="outgoing"
            )
            assert len(john_relations) == 2  # works_at and specializes_in
            print(f"   John has {len(john_relations)} outgoing relations")
            
            # Get incoming relations to AI concept
            ai_incoming = await uow.knowledge_relations.get_entity_relations(
                entity_id=entities[2].id,  # AI
                direction="incoming"
            )
            assert len(ai_incoming) == 2  # from John and TechCorp
            print(f"   AI concept has {len(ai_incoming)} incoming relations")
            
            # Get specific relation type
            work_relations = await uow.knowledge_relations.get_entity_relations(
                entity_id=entities[0].id,
                relation_type="works_at"
            )
            assert len(work_relations) == 1
            print(f"   Found {len(work_relations)} 'works_at' relations for John")
            
            # Test related entities discovery
            related_entities = await uow.knowledge_entities.get_related_entities(
                entity_id=entities[0].id,  # John
                limit=10
            )
            assert len(related_entities) == 2  # TechCorp and AI
            print(f"   John is related to {len(related_entities)} other entities")
            
            # Test relation types discovery
            relation_types = await uow.knowledge_relations.get_relation_types(kb.id)
            expected_types = {"works_at", "specializes_in", "develops"}
            assert set(relation_types) == expected_types
            print(f"   Knowledge base contains {len(relation_types)} relation types: {relation_types}")
            
            print("\n✅ Knowledge Graph integration tests passed!")
            
        break


async def test_document_vector_integration():
    """Test DocumentVector integration with knowledge base."""
    print("\n📄 Testing Document Vector Integration...")
    
    async for session in get_async_session():
        async with UnitOfWork(session) as uow:
            # Setup
            tenant = await uow.tenants.create(
                name="Vector Test Corp",
                slug="vector-test",
                is_active=True
            )
            
            user = await uow.users.create(
                external_id="vector_test_123",
                email="vector@example.com",
                username="vector_user",
                full_name="Vector Test User"
            )
            
            # Create knowledge base
            tenant_uow = uow.with_tenant(tenant.id)
            kb = await tenant_uow.knowledge_bases.create(
                name="vector_test_kb",
                display_name="Vector Test KB",
                vector_store_type="chroma",
                collection_name="vector_test_collection",
                embedding_model="sentence-transformers/all-MiniLM-L6-v2",
                embedding_dimension=384,
                owner_id=user.id
            )
            
            # Create a document
            doc = await tenant_uow.documents.create(
                owner_id=user.id,
                title="Vector Test Document",
                description="Document for testing vector integration"
            )
            
            print(f"   Created KB: {kb.display_name}")
            print(f"   Created document: {doc.title}")
            
            # Test DocumentVector CRUD
            print("\n   Testing DocumentVector operations...")
            
            # Create document vectors (simulating chunked document)
            vectors = []
            chunk_data = [
                {
                    "vector_id": f"vec_{uuid4().hex[:16]}",
                    "collection_name": kb.collection_name,
                    "content_type": "chunk",
                    "chunk_index": 0,
                    "chunk_text": "This is the first chunk of the document containing important information about AI.",
                    "chunk_start": 0,
                    "chunk_end": 85,
                    "token_count": 16,
                    "content_hash": "abc123def456"
                },
                {
                    "vector_id": f"vec_{uuid4().hex[:16]}",
                    "collection_name": kb.collection_name,
                    "content_type": "chunk",
                    "chunk_index": 1,
                    "chunk_text": "The second chunk discusses machine learning applications in modern software.",
                    "chunk_start": 86,
                    "chunk_end": 160,
                    "token_count": 12,
                    "content_hash": "def456ghi789"
                },
                {
                    "vector_id": f"vec_{uuid4().hex[:16]}",
                    "collection_name": kb.collection_name,
                    "content_type": "summary",
                    "chunk_index": None,
                    "chunk_text": "Document summary: Discussion of AI and ML applications.",
                    "token_count": 10,
                    "content_hash": "summary123"
                }
            ]
            
            for data in chunk_data:
                vector = await uow.document_vectors.create(
                    knowledge_base_id=kb.id,
                    document_id=doc.id,
                    embedding_model=kb.embedding_model,
                    embedding_dimension=kb.embedding_dimension,
                    embedding_created_at=datetime.utcnow(),
                    processing_status="completed",
                    **data
                )
                vectors.append(vector)
                print(f"     Created vector: {vector.content_type} (chunk {vector.chunk_index})")
            
            # Test vector retrieval
            print("\n   Testing vector retrieval...")
            
            # Get vectors by document
            doc_vectors = await uow.document_vectors.get_document_vectors(
                document_id=doc.id,
                knowledge_base_id=kb.id
            )
            assert len(doc_vectors) == 3
            print(f"     Document has {len(doc_vectors)} vectors")
            
            # Get vectors by collection
            collection_vectors = await uow.document_vectors.get_collection_vectors(
                collection_name=kb.collection_name,
                limit=100
            )
            assert len(collection_vectors) == 3
            print(f"     Collection has {len(collection_vectors)} vectors")
            
            # Get specific vector
            vector_by_id = await uow.document_vectors.get_by_vector_id(
                vectors[0].vector_id,
                kb.collection_name
            )
            assert vector_by_id.id == vectors[0].id
            print(f"     Retrieved vector by ID: {vector_by_id.vector_id}")
            
            # Test processing status updates
            success = await uow.document_vectors.update_processing_status(
                vectors[0].vector_id,
                "processing"
            )
            assert success == True
            print(f"     Updated vector processing status")
            
            # Test knowledge base statistics update
            print("\n   Testing knowledge base statistics...")
            
            success = await tenant_uow.knowledge_bases.update_statistics(
                kb.id,
                document_count=1,
                vector_count=3,
                entity_count=0,
                relation_count=0
            )
            assert success == True
            
            # Refresh and verify
            await session.refresh(kb)
            assert kb.document_count == 1
            assert kb.vector_count == 3
            print(f"     Updated KB stats: {kb.document_count} docs, {kb.vector_count} vectors")
            
            print("✅ Document Vector integration tests passed!")
            
        break


async def test_knowledge_base_user_access():
    """Test knowledge base access control and user permissions."""
    print("\n🔒 Testing Knowledge Base Access Control...")
    
    async for session in get_async_session():
        async with UnitOfWork(session) as uow:
            # Setup multiple users and teams
            tenant = await uow.tenants.create(
                name="Access Test Corp",
                slug="access-test",
                is_active=True
            )
            
            # Create users
            owner = await uow.users.create(
                external_id="kb_owner_123",
                email="owner@access.com",
                username="kb_owner",
                full_name="KB Owner"
            )
            
            member = await uow.users.create(
                external_id="kb_member_456",
                email="member@access.com",
                username="kb_member",
                full_name="KB Member"
            )
            
            # Create team
            tenant_uow = uow.with_tenant(tenant.id)
            team = await tenant_uow.teams.create(
                name="AI Research Team",
                slug="ai-research-team",
                description="Team for AI research",
                created_by=owner.id
            )
            
            print(f"   Created users: {owner.username}, {member.username}")
            print(f"   Created team: {team.name}")
            
            # Create knowledge bases with different access levels
            print("\n   Testing different access levels...")
            
            # Private KB (owner only)
            private_kb = await tenant_uow.knowledge_bases.create(
                name="private_research_kb",
                display_name="Private Research KB",
                description="Private knowledge base for sensitive research",
                vector_store_type="milvus",
                collection_name="private_collection",
                embedding_model="text-embedding-ada-002",
                embedding_dimension=1536,
                owner_id=owner.id,
                is_public=False
            )
            
            # Public KB
            public_kb = await tenant_uow.knowledge_bases.create(
                name="public_general_kb",
                display_name="Public General KB",
                description="Public knowledge base for general information",
                vector_store_type="milvus",
                collection_name="public_collection",
                embedding_model="text-embedding-ada-002",
                embedding_dimension=1536,
                owner_id=owner.id,
                is_public=True
            )
            
            # Team KB
            team_kb = await tenant_uow.knowledge_bases.create(
                name="team_ai_kb",
                display_name="Team AI KB",
                description="Knowledge base for AI research team",
                vector_store_type="milvus",
                collection_name="team_collection",
                embedding_model="text-embedding-ada-002",
                embedding_dimension=1536,
                owner_id=owner.id,
                team_id=team.id,
                is_public=False
            )
            
            print(f"     Created private KB: {private_kb.name}")
            print(f"     Created public KB: {public_kb.name}")
            print(f"     Created team KB: {team_kb.name}")
            
            # Test access for owner
            owner_kbs = await tenant_uow.knowledge_bases.get_user_knowledge_bases(
                user_id=owner.id,
                tenant_id=tenant.id,
                include_team=True
            )
            assert len(owner_kbs) == 3  # Owner can see all
            print(f"     Owner can access {len(owner_kbs)} knowledge bases")
            
            # Test access for member (should only see public)
            member_kbs = await tenant_uow.knowledge_bases.get_user_knowledge_bases(
                user_id=member.id,
                tenant_id=tenant.id,
                include_team=False
            )
            assert len(member_kbs) == 1  # Only public
            assert member_kbs[0].name == public_kb.name
            print(f"     Member can access {len(member_kbs)} knowledge bases (public only)")
            
            print("✅ Knowledge Base access control tests passed!")
            
        break


async def main():
    """Run all Knowledge Graph integration tests."""
    try:
        await test_knowledge_graph_integration()
        await test_document_vector_integration()
        await test_knowledge_base_user_access()
        print("\n🎉 All Knowledge Graph integration tests completed successfully!")
        return True
    except Exception as e:
        print(f"\n❌ Knowledge Graph tests failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)