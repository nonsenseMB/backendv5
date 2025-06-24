"""
Knowledge Graph and Vector Storage repositories.
"""

from uuid import UUID

from sqlalchemy import and_, desc, select
from sqlalchemy.orm import selectinload

from ..models.knowledge import DocumentVector, KnowledgeBase, KnowledgeEntity, KnowledgeRelation
from .base import BaseRepository, TenantAwareRepository


class KnowledgeBaseRepository(TenantAwareRepository[KnowledgeBase]):
    """Repository for knowledge base management."""

    async def get_by_name(self, name: str, tenant_id: UUID) -> KnowledgeBase | None:
        """Get knowledge base by name within tenant."""
        result = await self.session.execute(
            select(self.model)
            .where(and_(
                self.model.name == name,
                self.model.tenant_id == tenant_id
            ))
            .options(
                selectinload(self.model.owner),
                selectinload(self.model.team)
            )
        )
        return result.scalar_one_or_none()

    async def get_user_knowledge_bases(
        self,
        user_id: UUID,
        tenant_id: UUID,
        include_team: bool = True
    ) -> list[KnowledgeBase]:
        """Get knowledge bases accessible by user."""
        query = select(self.model).where(
            and_(
                self.model.tenant_id == tenant_id,
                self.model.is_active == True,
                (self.model.owner_id == user_id) | (self.model.is_public == True)
            )
        )

        if include_team:
            # TODO: Add team membership check
            pass

        return await self.session.execute(
            query.options(
                selectinload(self.model.owner),
                selectinload(self.model.team)
            )
            .order_by(desc(self.model.last_indexed_at))
        ).scalars().all()

    async def get_by_collection(self, collection_name: str) -> KnowledgeBase | None:
        """Get knowledge base by vector collection name."""
        return await self.session.execute(
            select(self.model)
            .where(self.model.collection_name == collection_name)
            .options(selectinload(self.model.owner))
        ).scalar_one_or_none()

    async def update_statistics(
        self,
        knowledge_base_id: UUID,
        document_count: int | None = None,
        vector_count: int | None = None,
        entity_count: int | None = None,
        relation_count: int | None = None
    ) -> bool:
        """Update knowledge base statistics."""
        kb = await self.get(knowledge_base_id)
        if not kb:
            return False

        if document_count is not None:
            kb.document_count = document_count
        if vector_count is not None:
            kb.vector_count = vector_count
        if entity_count is not None:
            kb.entity_count = entity_count
        if relation_count is not None:
            kb.relation_count = relation_count

        await self.session.commit()
        return True


class KnowledgeEntityRepository(BaseRepository[KnowledgeEntity]):
    """Repository for knowledge graph entities."""

    async def get_by_entity_id(
        self,
        entity_id: str,
        knowledge_base_id: UUID
    ) -> KnowledgeEntity | None:
        """Get entity by entity_id within knowledge base."""
        return await self.session.execute(
            select(self.model)
            .where(and_(
                self.model.entity_id == entity_id,
                self.model.knowledge_base_id == knowledge_base_id
            ))
        ).scalar_one_or_none()

    async def search_entities(
        self,
        knowledge_base_id: UUID,
        query: str,
        entity_type: str | None = None,
        limit: int = 20
    ) -> list[KnowledgeEntity]:
        """Search entities by name or canonical name."""
        filters = [
            self.model.knowledge_base_id == knowledge_base_id,
            self.model.is_active == True,
            (self.model.name.ilike(f'%{query}%') |
             self.model.canonical_name.ilike(f'%{query}%'))
        ]

        if entity_type:
            filters.append(self.model.entity_type == entity_type)

        return await self.session.execute(
            select(self.model)
            .where(and_(*filters))
            .order_by(desc(self.model.confidence_score))
            .limit(limit)
        ).scalars().all()

    async def get_entities_by_type(
        self,
        knowledge_base_id: UUID,
        entity_type: str,
        limit: int = 100
    ) -> list[KnowledgeEntity]:
        """Get entities of specific type."""
        return await self.session.execute(
            select(self.model)
            .where(and_(
                self.model.knowledge_base_id == knowledge_base_id,
                self.model.entity_type == entity_type,
                self.model.is_active == True
            ))
            .order_by(self.model.name)
            .limit(limit)
        ).scalars().all()

    async def get_related_entities(
        self,
        entity_id: UUID,
        relation_types: list[str] | None = None,
        limit: int = 20
    ) -> list[dict]:
        """Get entities related to given entity."""
        # This would typically involve AGE graph queries
        # For now, return related entities through knowledge relations
        query = select(
            self.model,
            KnowledgeRelation.relation_type
        ).join(
            KnowledgeRelation,
            (KnowledgeRelation.source_entity_id == entity_id) |
            (KnowledgeRelation.target_entity_id == entity_id)
        ).where(
            and_(
                self.model.id != entity_id,
                self.model.is_active == True,
                KnowledgeRelation.is_active == True
            )
        )

        if relation_types:
            query = query.where(KnowledgeRelation.relation_type.in_(relation_types))

        results = await self.session.execute(query.limit(limit)).all()

        return [
            {
                'entity': result[0],
                'relation_type': result[1],
                'confidence': result[0].confidence_score
            }
            for result in results
        ]


class KnowledgeRelationRepository(BaseRepository[KnowledgeRelation]):
    """Repository for knowledge graph relations."""

    async def get_by_relation_id(
        self,
        relation_id: str,
        knowledge_base_id: UUID
    ) -> KnowledgeRelation | None:
        """Get relation by relation_id within knowledge base."""
        return await self.session.execute(
            select(self.model)
            .where(and_(
                self.model.relation_id == relation_id,
                self.model.knowledge_base_id == knowledge_base_id
            ))
            .options(
                selectinload(self.model.source_entity),
                selectinload(self.model.target_entity)
            )
        ).scalar_one_or_none()

    async def get_entity_relations(
        self,
        entity_id: UUID,
        relation_type: str | None = None,
        direction: str = 'both'  # 'incoming', 'outgoing', 'both'
    ) -> list[KnowledgeRelation]:
        """Get relations for an entity."""
        filters = [self.model.is_active == True]

        if direction == 'incoming':
            filters.append(self.model.target_entity_id == entity_id)
        elif direction == 'outgoing':
            filters.append(self.model.source_entity_id == entity_id)
        else:  # both
            filters.append(
                (self.model.source_entity_id == entity_id) |
                (self.model.target_entity_id == entity_id)
            )

        if relation_type:
            filters.append(self.model.relation_type == relation_type)

        return await self.session.execute(
            select(self.model)
            .where(and_(*filters))
            .options(
                selectinload(self.model.source_entity),
                selectinload(self.model.target_entity)
            )
            .order_by(desc(self.model.confidence_score))
        ).scalars().all()

    async def find_paths(
        self,
        source_entity_id: UUID,
        target_entity_id: UUID,
        max_depth: int = 3
    ) -> list[list[KnowledgeRelation]]:
        """Find paths between two entities (simplified version)."""
        # This would typically use AGE graph path queries
        # For now, implement a simple 1-hop or 2-hop search
        paths = []

        # Direct path
        direct_relations = await self.session.execute(
            select(self.model)
            .where(and_(
                self.model.source_entity_id == source_entity_id,
                self.model.target_entity_id == target_entity_id,
                self.model.is_active == True
            ))
        ).scalars().all()

        for relation in direct_relations:
            paths.append([relation])

        # TODO: Implement multi-hop paths using AGE
        return paths

    async def get_relation_types(self, knowledge_base_id: UUID) -> list[str]:
        """Get all relation types in knowledge base."""
        result = await self.session.execute(
            select(self.model.relation_type)
            .where(and_(
                self.model.knowledge_base_id == knowledge_base_id,
                self.model.is_active == True
            ))
            .distinct()
        )
        return result.scalars().all()


class DocumentVectorRepository(BaseRepository[DocumentVector]):
    """Repository for document vector references."""

    async def get_by_vector_id(
        self,
        vector_id: str,
        collection_name: str
    ) -> DocumentVector | None:
        """Get document vector by vector ID and collection."""
        return await self.session.execute(
            select(self.model)
            .where(and_(
                self.model.vector_id == vector_id,
                self.model.collection_name == collection_name
            ))
            .options(
                selectinload(self.model.document),
                selectinload(self.model.knowledge_base)
            )
        ).scalar_one_or_none()

    async def get_document_vectors(
        self,
        document_id: UUID,
        knowledge_base_id: UUID | None = None
    ) -> list[DocumentVector]:
        """Get all vectors for a document."""
        filters = [self.model.document_id == document_id]

        if knowledge_base_id:
            filters.append(self.model.knowledge_base_id == knowledge_base_id)

        return await self.session.execute(
            select(self.model)
            .where(and_(*filters))
            .options(selectinload(self.model.knowledge_base))
            .order_by(self.model.chunk_index)
        ).scalars().all()

    async def get_collection_vectors(
        self,
        collection_name: str,
        limit: int = 100,
        offset: int = 0
    ) -> list[DocumentVector]:
        """Get vectors in a collection."""
        return await self.session.execute(
            select(self.model)
            .where(self.model.collection_name == collection_name)
            .options(
                selectinload(self.model.document),
                selectinload(self.model.knowledge_base)
            )
            .order_by(self.model.created_at)
            .limit(limit)
            .offset(offset)
        ).scalars().all()

    async def update_processing_status(
        self,
        vector_id: str,
        collection_name: str,
        status: str,
        error_message: str | None = None
    ) -> bool:
        """Update processing status for vector."""
        vector = await self.get_by_vector_id(vector_id, collection_name)
        if not vector:
            return False

        vector.processing_status = status
        if error_message:
            vector.error_message = error_message

        await self.session.commit()
        return True
