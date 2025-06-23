"""
Knowledge Graph and Vector Storage models.
Integrates Apache AGE for graph queries and Milvus for vector search.
"""

from sqlalchemy import JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from ..base import BaseModel, TenantAwareModel


class KnowledgeBase(TenantAwareModel):
    """
    Knowledge base configuration and metadata.
    References vector storage collections in Milvus/Chroma.
    """
    __tablename__ = 'knowledge_bases'

    # Identity
    name = Column(String(255), nullable=False)
    display_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Vector Storage Configuration
    vector_store_type = Column(String(50), nullable=False, default='milvus')  # milvus, chroma
    collection_name = Column(String(255), nullable=False)
    embedding_model = Column(String(100), nullable=False)
    embedding_dimension = Column(Integer, nullable=False)

    # Graph Configuration
    graph_name = Column(String(255), nullable=True)  # Apache AGE graph name
    enable_graph_queries = Column(Boolean, default=True)

    # Processing Settings
    chunk_size = Column(Integer, default=1000)
    chunk_overlap = Column(Integer, default=100)
    auto_processing = Column(Boolean, default=True)

    # Access Control
    is_public = Column(Boolean, default=False)
    owner_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    team_id = Column(UUID(as_uuid=True), ForeignKey('teams.id'), nullable=True)

    # Statistics
    document_count = Column(Integer, default=0)
    vector_count = Column(Integer, default=0)
    entity_count = Column(Integer, default=0)
    relation_count = Column(Integer, default=0)

    # Status
    is_active = Column(Boolean, default=True)
    last_indexed_at = Column(DateTime, nullable=True)
    indexing_status = Column(String(50), default='idle')  # idle, processing, error

    # Additional data
    extra_data = Column('metadata', JSON, default=dict)

    # Relationships
    owner = relationship("User")
    team = relationship("Team")
    entities = relationship("KnowledgeEntity", back_populates="knowledge_base", cascade="all, delete-orphan")
    relations = relationship("KnowledgeRelation", back_populates="knowledge_base", cascade="all, delete-orphan")
    document_vectors = relationship("DocumentVector", back_populates="knowledge_base", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<KnowledgeBase(name='{self.name}', collection='{self.collection_name}')>"


class KnowledgeEntity(BaseModel):
    """
    Entities extracted from documents for the knowledge graph.
    Integrated with Apache AGE for relationship queries.
    """
    __tablename__ = 'knowledge_entities'

    # Foreign Key
    knowledge_base_id = Column(UUID(as_uuid=True), ForeignKey('knowledge_bases.id', ondelete='CASCADE'), nullable=False)

    # Entity Identity
    entity_id = Column(String(255), nullable=False)  # Unique within knowledge base
    entity_type = Column(String(100), nullable=False)  # person, organization, concept, topic
    name = Column(String(500), nullable=False)
    canonical_name = Column(String(500), nullable=True)  # Normalized name

    # Properties
    properties = Column(JSON, default=dict)  # Key-value properties
    aliases = Column(JSON, default=list)  # Alternative names
    description = Column(Text, nullable=True)

    # Source Information
    source_documents = Column(JSON, default=list)  # Document IDs where entity appears
    confidence_score = Column(Float, default=1.0)  # Extraction confidence
    extraction_method = Column(String(50), nullable=True)  # ner, manual, import

    # Graph Node ID (Apache AGE)
    age_node_id = Column(String(255), nullable=True)  # AGE graph node identifier
    age_label = Column(String(100), nullable=True)  # AGE node label

    # Vector Embedding
    has_embedding = Column(Boolean, default=False)
    embedding_model = Column(String(100), nullable=True)

    # Status
    is_verified = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)

    # Additional data
    extra_data = Column('metadata', JSON, default=dict)

    # Relationships
    knowledge_base = relationship("KnowledgeBase", back_populates="entities")
    source_relations = relationship("KnowledgeRelation", foreign_keys="KnowledgeRelation.source_entity_id", back_populates="source_entity")
    target_relations = relationship("KnowledgeRelation", foreign_keys="KnowledgeRelation.target_entity_id", back_populates="target_entity")

    def __repr__(self):
        return f"<KnowledgeEntity(name='{self.name}', type='{self.entity_type}')>"


class KnowledgeRelation(BaseModel):
    """
    Relationships between entities in the knowledge graph.
    Stored as edges in Apache AGE.
    """
    __tablename__ = 'knowledge_relations'

    # Foreign Key
    knowledge_base_id = Column(UUID(as_uuid=True), ForeignKey('knowledge_bases.id', ondelete='CASCADE'), nullable=False)

    # Relation Identity
    relation_id = Column(String(255), nullable=False)  # Unique within knowledge base
    relation_type = Column(String(100), nullable=False)  # works_at, authored, relates_to

    # Source and Target
    source_entity_id = Column(UUID(as_uuid=True), ForeignKey('knowledge_entities.id'), nullable=False)
    target_entity_id = Column(UUID(as_uuid=True), ForeignKey('knowledge_entities.id'), nullable=False)

    # Relation Properties
    properties = Column(JSON, default=dict)  # Relation-specific data
    weight = Column(Float, default=1.0)  # Relationship strength
    confidence_score = Column(Float, default=1.0)  # Extraction confidence

    # Source Information
    source_documents = Column(JSON, default=list)  # Documents where relation appears
    extraction_method = Column(String(50), nullable=True)  # pattern, llm, manual

    # Graph Edge ID (Apache AGE)
    age_edge_id = Column(String(255), nullable=True)  # AGE graph edge identifier
    age_label = Column(String(100), nullable=True)  # AGE edge label

    # Temporal Information
    valid_from = Column(DateTime, nullable=True)
    valid_to = Column(DateTime, nullable=True)

    # Status
    is_verified = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)

    # Additional data
    extra_data = Column('metadata', JSON, default=dict)

    # Relationships
    knowledge_base = relationship("KnowledgeBase", back_populates="relations")
    source_entity = relationship("KnowledgeEntity", foreign_keys=[source_entity_id], back_populates="source_relations")
    target_entity = relationship("KnowledgeEntity", foreign_keys=[target_entity_id], back_populates="target_relations")

    def __repr__(self):
        return f"<KnowledgeRelation(type='{self.relation_type}', source={self.source_entity_id}, target={self.target_entity_id})>"


class DocumentVector(BaseModel):
    """
    References to document vectors stored in Milvus/Chroma.
    Links PostgreSQL documents to vector embeddings.
    """
    __tablename__ = 'document_vectors'

    # Foreign Keys
    knowledge_base_id = Column(UUID(as_uuid=True), ForeignKey('knowledge_bases.id', ondelete='CASCADE'), nullable=False)
    document_id = Column(UUID(as_uuid=True), ForeignKey('documents.id', ondelete='CASCADE'), nullable=True)

    # Vector Storage Reference
    vector_id = Column(String(255), nullable=False)  # ID in vector store
    collection_name = Column(String(255), nullable=False)
    chunk_index = Column(Integer, nullable=True)  # For document chunks

    # Content Information
    content_type = Column(String(50), nullable=False, default='document')  # document, chunk, summary
    content_hash = Column(String(64), nullable=True)  # SHA256 of content
    token_count = Column(Integer, nullable=True)

    # Embedding Model
    embedding_model = Column(String(100), nullable=False)
    embedding_dimension = Column(Integer, nullable=False)
    embedding_created_at = Column(DateTime, nullable=False)

    # Chunk Information (for document chunks)
    chunk_text = Column(Text, nullable=True)  # Actual text content
    chunk_start = Column(Integer, nullable=True)  # Character start position
    chunk_end = Column(Integer, nullable=True)  # Character end position

    # Processing Status
    processing_status = Column(String(50), default='completed')  # pending, processing, completed, error
    error_message = Column(Text, nullable=True)

    # Additional data
    extra_data = Column('metadata', JSON, default=dict)

    # Relationships
    knowledge_base = relationship("KnowledgeBase", back_populates="document_vectors")
    document = relationship("Document")

    def __repr__(self):
        return f"<DocumentVector(vector_id='{self.vector_id}', collection='{self.collection_name}')>"
