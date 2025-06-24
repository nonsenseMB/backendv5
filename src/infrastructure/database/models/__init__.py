"""
Database models package.
Import all models here for Alembic auto-discovery.
"""

from .agent import Agent
from .audit_log import AuditLog, AuditLogQuery, AuditLogRetentionPolicy
from .auth import User, UserDevice
from .conversation import Conversation, ConversationCheckpoint, Message
from .document import Document, DocumentContent, DocumentPermission, DocumentShare
from .knowledge import DocumentVector, KnowledgeBase, KnowledgeEntity, KnowledgeRelation
from .llm import LLMAPIKey, LLMProvider
from .memory import UserPreferences
from .permission import Permission, ResourcePermission, Role, RolePermission, UserRole
from .team import Team, TeamMember
from .tenant import Tenant, TenantUser
from .tool import MCPServer, Tool, ToolDefinition, ToolExecution
from .user_session import SessionActivity, SessionSecurityEvent, UserSession

__all__ = [
    # Tenant models
    "Tenant",
    "TenantUser",
    # Auth models
    "User",
    "UserDevice",
    # Session models
    "UserSession",
    "SessionActivity",
    "SessionSecurityEvent",
    # Audit logging models
    "AuditLog",
    "AuditLogQuery",
    "AuditLogRetentionPolicy",
    # Permission models
    "Permission",
    "Role",
    "RolePermission",
    "UserRole",
    "ResourcePermission",
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
    # Document System models
    "Document",
    "DocumentContent",
    "DocumentPermission",
    "DocumentShare",
    # Knowledge Graph models
    "KnowledgeBase",
    "KnowledgeEntity",
    "KnowledgeRelation",
    "DocumentVector",
    # Tool System models
    "Tool",
    "ToolDefinition",
    "MCPServer",
    "ToolExecution",
]
