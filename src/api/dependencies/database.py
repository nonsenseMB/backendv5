"""Database dependencies for FastAPI endpoints."""
from src.infrastructure.database.session import get_async_session

# Re-export for easier access
__all__ = ["get_async_session"]
