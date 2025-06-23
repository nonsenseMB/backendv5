"""
Base models for the database layer.
All models inherit from these base classes.
"""
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Column, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base, declared_attr
from sqlalchemy.orm import relationship

Base = declarative_base()


class BaseModel(Base):
    """
    Base model with common fields for all database models.
    Provides id, created_at, and updated_at fields.
    """
    __abstract__ = True

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        """Convert model to dictionary."""
        result = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            if isinstance(value, datetime):
                value = value.isoformat()
            elif isinstance(value, uuid.UUID):
                value = str(value)
            result[column.name] = value
        return result

    def __repr__(self):
        return f"<{self.__class__.__name__}(id={self.id})>"


class TenantAwareModel(BaseModel):
    """
    Base model for all tenant-aware models.
    Adds tenant_id field and ensures tenant isolation.
    """
    __abstract__ = True

    @declared_attr
    def tenant_id(cls):
        return Column(UUID(as_uuid=True), ForeignKey('tenants.id'), nullable=False, index=True)

    @declared_attr
    def tenant(cls):
        return relationship("Tenant", lazy="selectin")
