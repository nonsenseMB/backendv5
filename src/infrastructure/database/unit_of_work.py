"""
Unit of Work pattern for managing database transactions.
"""
from typing import Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from infrastructure.database.repositories.user import UserRepository, UserDeviceRepository
from infrastructure.database.repositories.tenant import TenantRepository, TenantUserRepository
from infrastructure.database.repositories.conversation import (
    ConversationRepository,
    MessageRepository,
    ConversationCheckpointRepository
)
from infrastructure.database.repositories.llm import LLMProviderRepository, LLMAPIKeyRepository
from infrastructure.database.repositories.memory import UserPreferencesRepository
from infrastructure.database.repositories.agent import AgentRepository
from infrastructure.database.repositories.team import TeamRepository, TeamMemberRepository

from infrastructure.database.models.auth import User, UserDevice
from infrastructure.database.models.tenant import Tenant, TenantUser
from infrastructure.database.models.conversation import Conversation, Message, ConversationCheckpoint
from infrastructure.database.models.llm import LLMProvider, LLMAPIKey
from infrastructure.database.models.memory import UserPreferences
from infrastructure.database.models.agent import Agent
from infrastructure.database.models.team import Team, TeamMember


class UnitOfWork:
    """
    Unit of Work pattern implementation.
    
    Manages database transactions and provides access to repositories.
    """
    
    def __init__(self, session: AsyncSession, tenant_id: Optional[UUID] = None):
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
        
        # Tenant-aware repositories
        if tenant_id:
            self.tenant_users = TenantUserRepository(TenantUser, session, tenant_id)
            self.conversations = ConversationRepository(Conversation, session, tenant_id)
            self.llm_providers = LLMProviderRepository(LLMProvider, session, tenant_id)
            self.agents = AgentRepository(Agent, session, tenant_id)
            self.teams = TeamRepository(Team, session, tenant_id)
        else:
            self.tenant_users = None
            self.conversations = None
            self.llm_providers = None
            self.agents = None
            self.teams = None
    
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


async def get_unit_of_work(session: AsyncSession, tenant_id: Optional[UUID] = None) -> UnitOfWork:
    """
    Factory function to create a UnitOfWork instance.
    
    Args:
        session: Database session
        tenant_id: Optional tenant ID for tenant-aware operations
        
    Returns:
        UnitOfWork instance
    """
    return UnitOfWork(session, tenant_id)