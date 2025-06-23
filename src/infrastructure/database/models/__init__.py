"""
Database models package.
Import all models here for Alembic auto-discovery.
"""

from .tenant import Tenant, TenantUser
from .auth import User, UserDevice
from .llm import LLMProvider, LLMAPIKey
from .conversation import Conversation, Message, ConversationCheckpoint
from .memory import UserPreferences
from .team import Team, TeamMember
from .agent import Agent

__all__ = [
    # Tenant models
    "Tenant",
    "TenantUser",
    # Auth models
    "User", 
    "UserDevice",
    # LLM models
    "LLMProvider",
    "LLMAPIKey",
    # Conversation models
    "Conversation",
    "Message",
    "ConversationCheckpoint",
    # Memory models (only user preferences - actual memory is in vector DB)
    "UserPreferences",
    # Team models
    "Team",
    "TeamMember",
    # Agent models
    "Agent",
]