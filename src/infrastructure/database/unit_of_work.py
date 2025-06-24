"""
Unit of Work pattern for managing database transactions.
"""
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from src.infrastructure.database.models.agent import Agent
from src.infrastructure.database.models.auth import User, UserDevice
from src.infrastructure.database.models.conversation import Conversation, ConversationCheckpoint, Message
from src.infrastructure.database.models.document import Document, DocumentContent, DocumentPermission, DocumentShare
from src.infrastructure.database.models.knowledge import DocumentVector, KnowledgeBase, KnowledgeEntity, KnowledgeRelation
from src.infrastructure.database.models.llm import LLMAPIKey, LLMProvider
from src.infrastructure.database.models.memory import UserPreferences
from src.infrastructure.database.models.team import Team, TeamMember
from src.infrastructure.database.models.tenant import Tenant, TenantUser
from src.infrastructure.database.models.tool import MCPServer, Tool, ToolDefinition, ToolExecution
from src.infrastructure.database.repositories.agent import AgentRepository
from src.infrastructure.database.repositories.conversation import (
    ConversationCheckpointRepository,
    ConversationRepository,
    MessageRepository,
)
from src.infrastructure.database.repositories.document import (
    DocumentContentRepository,
    DocumentPermissionRepository,
    DocumentRepository,
    DocumentShareRepository,
)
from src.infrastructure.database.repositories.knowledge import (
    DocumentVectorRepository,
    KnowledgeBaseRepository,
    KnowledgeEntityRepository,
    KnowledgeRelationRepository,
)
from src.infrastructure.database.repositories.llm import LLMAPIKeyRepository, LLMProviderRepository
from src.infrastructure.database.repositories.memory import UserPreferencesRepository
from src.infrastructure.database.repositories.team import TeamMemberRepository, TeamRepository
from src.infrastructure.database.repositories.tenant import TenantRepository, TenantUserRepository
from src.infrastructure.database.repositories.tool import (
    MCPServerRepository,
    ToolDefinitionRepository,
    ToolExecutionRepository,
    ToolRepository,
)
from src.infrastructure.database.repositories.user import UserDeviceRepository, UserRepository


class UnitOfWork:
    """
    Unit of Work pattern implementation.

    Manages database transactions and provides access to repositories.
    """

    def __init__(self, session: AsyncSession, tenant_id: UUID | None = None):
        self.session = session
        self.tenant_id = tenant_id

        # Initialize repositories
        self.users = UserRepository(User, session)
        self.user_devices = UserDeviceRepository(UserDevice, session)
        self.user_preferences = UserPreferencesRepository(UserPreferences, session)
        self.tenants = TenantRepository(Tenant, session)

        # Non-tenant repositories
        self.messages = MessageRepository(Message, session)
        self.checkpoints = ConversationCheckpointRepository(ConversationCheckpoint, session)
        self.llm_api_keys = LLMAPIKeyRepository(LLMAPIKey, session)
        self.team_members = TeamMemberRepository(TeamMember, session)
        self.document_content = DocumentContentRepository(DocumentContent, session)
        self.document_permissions = DocumentPermissionRepository(DocumentPermission, session)
        self.document_shares = DocumentShareRepository(DocumentShare, session)
        self.knowledge_entities = KnowledgeEntityRepository(KnowledgeEntity, session)
        self.knowledge_relations = KnowledgeRelationRepository(KnowledgeRelation, session)
        self.document_vectors = DocumentVectorRepository(DocumentVector, session)
        self.tool_definitions = ToolDefinitionRepository(ToolDefinition, session)
        self.tool_executions = ToolExecutionRepository(ToolExecution, session)

        # Tenant-aware repositories
        if tenant_id:
            self.tenant_users = TenantUserRepository(TenantUser, session, tenant_id)
            self.conversations = ConversationRepository(Conversation, session, tenant_id)
            self.llm_providers = LLMProviderRepository(LLMProvider, session, tenant_id)
            self.agents = AgentRepository(Agent, session, tenant_id)
            self.teams = TeamRepository(Team, session, tenant_id)
            self.documents = DocumentRepository(Document, session, tenant_id)
            self.knowledge_bases = KnowledgeBaseRepository(KnowledgeBase, session, tenant_id)
            self.tools = ToolRepository(Tool, session, tenant_id)
            self.mcp_servers = MCPServerRepository(MCPServer, session, tenant_id)
        else:
            self.tenant_users = None
            self.conversations = None
            self.llm_providers = None
            self.agents = None
            self.teams = None
            self.documents = None
            self.knowledge_bases = None
            self.tools = None
            self.mcp_servers = None

    async def __aenter__(self):
        """Enter the context manager."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit the context manager."""
        if exc_type:
            await self.rollback()
        else:
            await self.commit()

    async def commit(self):
        """Commit the transaction."""
        await self.session.commit()

    async def rollback(self):
        """Rollback the transaction."""
        await self.session.rollback()

    async def flush(self):
        """Flush pending changes without committing."""
        await self.session.flush()

    def with_tenant(self, tenant_id: UUID) -> 'UnitOfWork':
        """
        Create a new UnitOfWork instance for a specific tenant.

        This is useful when you need to switch tenant context.
        """
        return UnitOfWork(self.session, tenant_id)


async def get_unit_of_work(session: AsyncSession, tenant_id: UUID | None = None) -> UnitOfWork:
    """
    Factory function to create a UnitOfWork instance.

    Args:
        session: Database session
        tenant_id: Optional tenant ID for tenant-aware operations

    Returns:
        UnitOfWork instance
    """
    return UnitOfWork(session, tenant_id)
