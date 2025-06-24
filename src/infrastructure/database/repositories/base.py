"""
Base CRUD repository with async support.
"""
from typing import Any, Generic, TypeVar
from uuid import UUID

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.infrastructure.database.base import Base

ModelType = TypeVar("ModelType", bound=Base)


class BaseRepository(Generic[ModelType]):
    """Base repository providing CRUD operations."""

    def __init__(self, model: type[ModelType], session: AsyncSession):
        self.model = model
        self.session = session

    async def get(self, id: UUID, load_relationships: list[str] = None) -> ModelType | None:
        """
        Get a single record by ID.

        Args:
            id: Record ID
            load_relationships: List of relationship names to eager load

        Returns:
            Model instance or None
        """
        query = select(self.model).where(self.model.id == id)

        if load_relationships:
            for rel in load_relationships:
                query = query.options(selectinload(getattr(self.model, rel)))

        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_by(self, **kwargs) -> ModelType | None:
        """
        Get a single record by field values.

        Args:
            **kwargs: Field name-value pairs to filter by

        Returns:
            Model instance or None
        """
        query = select(self.model)
        for key, value in kwargs.items():
            query = query.where(getattr(self.model, key) == value)

        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_multi(
        self,
        skip: int = 0,
        limit: int = 100,
        filters: dict[str, Any] = None,
        order_by: str = None,
        load_relationships: list[str] = None
    ) -> list[ModelType]:
        """
        Get multiple records with pagination and filtering.

        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            filters: Dictionary of field filters
            order_by: Field name to order by (prefix with - for DESC)
            load_relationships: List of relationship names to eager load

        Returns:
            List of model instances
        """
        query = select(self.model)

        # Apply filters
        if filters:
            for key, value in filters.items():
                if value is not None:
                    query = query.where(getattr(self.model, key) == value)

        # Apply ordering
        if order_by:
            if order_by.startswith("-"):
                query = query.order_by(getattr(self.model, order_by[1:]).desc())
            else:
                query = query.order_by(getattr(self.model, order_by))
        else:
            # Default ordering by created_at desc
            if hasattr(self.model, 'created_at'):
                query = query.order_by(self.model.created_at.desc())

        # Apply pagination
        query = query.offset(skip).limit(limit)

        # Eager load relationships
        if load_relationships:
            for rel in load_relationships:
                query = query.options(selectinload(getattr(self.model, rel)))

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def count(self, filters: dict[str, Any] = None) -> int:
        """
        Count records with optional filtering.

        Args:
            filters: Dictionary of field filters

        Returns:
            Number of records
        """
        query = select(func.count()).select_from(self.model)

        if filters:
            for key, value in filters.items():
                if value is not None:
                    query = query.where(getattr(self.model, key) == value)

        result = await self.session.execute(query)
        return result.scalar()

    async def create(self, **kwargs) -> ModelType:
        """
        Create a new record.

        Args:
            **kwargs: Field values for the new record

        Returns:
            Created model instance
        """
        db_obj = self.model(**kwargs)
        self.session.add(db_obj)
        await self.session.flush()
        return db_obj

    async def update(
        self,
        id: UUID,
        **kwargs
    ) -> ModelType | None:
        """
        Update a record by ID.

        Args:
            id: Record ID
            **kwargs: Field values to update

        Returns:
            Updated model instance or None
        """
        # Remove None values
        update_data = {k: v for k, v in kwargs.items() if v is not None}

        if not update_data:
            return await self.get(id)

        query = (
            update(self.model)
            .where(self.model.id == id)
            .values(**update_data)
            .returning(self.model)
        )

        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def delete(self, id: UUID) -> bool:
        """
        Delete a record by ID.

        Args:
            id: Record ID

        Returns:
            True if deleted, False if not found
        """
        query = delete(self.model).where(self.model.id == id)
        result = await self.session.execute(query)
        return result.rowcount > 0

    async def exists(self, **kwargs) -> bool:
        """
        Check if a record exists.

        Args:
            **kwargs: Field name-value pairs to check

        Returns:
            True if exists, False otherwise
        """
        query = select(func.count()).select_from(self.model)
        for key, value in kwargs.items():
            query = query.where(getattr(self.model, key) == value)

        result = await self.session.execute(query)
        return result.scalar() > 0


class TenantAwareRepository(BaseRepository[ModelType]):
    """Base repository for tenant-aware models."""

    def __init__(self, model: type[ModelType], session: AsyncSession, tenant_id: UUID | None = None):
        super().__init__(model, session)

        # If no tenant_id provided, try to get from context
        if tenant_id is None:
            from src.core.context import get_tenant_context
            context_tenant_id = get_tenant_context()
            if context_tenant_id:
                from uuid import UUID
                self.tenant_id = UUID(context_tenant_id)
            else:
                raise ValueError("Tenant ID is required for TenantAwareRepository")
        else:
            self.tenant_id = tenant_id

    async def get(self, id: UUID, load_relationships: list[str] = None) -> ModelType | None:
        """Get a record by ID within the current tenant."""
        query = select(self.model).where(
            self.model.id == id,
            self.model.tenant_id == self.tenant_id
        )

        if load_relationships:
            for rel in load_relationships:
                query = query.options(selectinload(getattr(self.model, rel)))

        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_multi(
        self,
        skip: int = 0,
        limit: int = 100,
        filters: dict[str, Any] = None,
        order_by: str = None,
        load_relationships: list[str] = None
    ) -> list[ModelType]:
        """Get multiple records within the current tenant."""
        if filters is None:
            filters = {}
        filters['tenant_id'] = self.tenant_id

        return await super().get_multi(skip, limit, filters, order_by, load_relationships)

    async def count(self, filters: dict[str, Any] = None) -> int:
        """Count records within the current tenant."""
        if filters is None:
            filters = {}
        filters['tenant_id'] = self.tenant_id

        return await super().count(filters)

    async def create(self, **kwargs) -> ModelType:
        """Create a record within the current tenant."""
        kwargs['tenant_id'] = self.tenant_id
        return await super().create(**kwargs)

    async def update(self, id: UUID, **kwargs) -> ModelType | None:
        """Update a record within the current tenant."""
        # Ensure we're updating within the same tenant
        existing = await self.get(id)
        if not existing:
            return None

        return await super().update(id, **kwargs)

    async def delete(self, id: UUID) -> bool:
        """Delete a record within the current tenant."""
        query = delete(self.model).where(
            self.model.id == id,
            self.model.tenant_id == self.tenant_id
        )
        result = await self.session.execute(query)
        return result.rowcount > 0
