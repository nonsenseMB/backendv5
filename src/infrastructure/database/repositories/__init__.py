"""
Database repositories.
"""
from .agent import AgentRepository
from .base import BaseRepository, TenantAwareRepository
from .conversation import ConversationCheckpointRepository, ConversationRepository, MessageRepository
from .document import (
    DocumentContentRepository,
    DocumentPermissionRepository,
    DocumentRepository,
    DocumentShareRepository,
)
from .knowledge import (
    DocumentVectorRepository,
    KnowledgeBaseRepository,
    KnowledgeEntityRepository,
    KnowledgeRelationRepository,
)
from .llm import LLMAPIKeyRepository, LLMProviderRepository
from .memory import UserPreferencesRepository
from .team import TeamMemberRepository, TeamRepository
from .tenant import TenantRepository, TenantUserRepository
from .tool import MCPServerRepository, ToolDefinitionRepository, ToolExecutionRepository, ToolRepository
from .user import UserDeviceRepository, UserRepository

__all__ = [
    # Base
    'BaseRepository',
    'TenantAwareRepository',
    # User
    'UserRepository',
    'UserDeviceRepository',
    # Tenant
    'TenantRepository',
    'TenantUserRepository',
    # Conversation
    'ConversationRepository',
    'MessageRepository',
    'ConversationCheckpointRepository',
    # LLM
    'LLMProviderRepository',
    'LLMAPIKeyRepository',
    # Memory (only user preferences - actual memory is in vector DB)
    'UserPreferencesRepository',
    # Agent
    'AgentRepository',
    # Team
    'TeamRepository',
    'TeamMemberRepository',
    # Document System
    'DocumentRepository',
    'DocumentContentRepository',
    'DocumentPermissionRepository',
    'DocumentShareRepository',
    # Knowledge Graph
    'KnowledgeBaseRepository',
    'KnowledgeEntityRepository',
    'KnowledgeRelationRepository',
    'DocumentVectorRepository',
    # Tool System
    'ToolRepository',
    'ToolDefinitionRepository',
    'MCPServerRepository',
    'ToolExecutionRepository',
]
