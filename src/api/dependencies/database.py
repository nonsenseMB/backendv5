"""Database dependencies for FastAPI endpoints."""
from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies.tenant import get_current_tenant_id
from src.infrastructure.database.session import get_async_session
from src.infrastructure.database.unit_of_work import UnitOfWork

# Re-export for easier access
__all__ = ["get_async_session", "get_uow"]


async def get_uow(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    tenant_id: Annotated[str | None, Depends(get_current_tenant_id)]
) -> UnitOfWork:
    """Get Unit of Work for database operations."""
    return UnitOfWork(session, tenant_id)
