"""Domain models for authentication.

These are aliases to the database models for use in the API layer.
"""
from src.infrastructure.database.models.auth import User, UserDevice

__all__ = ["User", "UserDevice"]
