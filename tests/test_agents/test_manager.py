"""
Tests for agent manager functionality.
"""
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import pytest

from src.agents.exceptions import AgentNotFoundError, ValidationError
from src.agents.manager import AgentManager
from src.core.auth.exceptions import InsufficientPermissionsError
from src.infrastructure.database.models.agent import Agent, AgentMemory
from src.infrastructure.database.uow import UnitOfWork


class TestAgentManager:
    """Test agent manager functionality."""
    
    @pytest.fixture
    def mock_loader(self):
        """Mock agent loader."""
        loader = MagicMock()
        loader.validate_agent_definition.return_value = []  # No errors
        return loader
    
    @pytest.fixture
    def mock_executor(self):
        """Mock agent executor."""
        return MagicMock()
    
    @pytest.fixture
    def manager(self, mock_loader, mock_executor):
        """Create agent manager with mocked dependencies."""
        return AgentManager(
            loader=mock_loader,
            executor=mock_executor
        )
    
    @pytest.fixture
    def mock_uow(self):
        """Mock unit of work."""
        uow = AsyncMock(spec=UnitOfWork)
        uow.agents = AsyncMock()
        uow.session = AsyncMock()
        return uow
    
    @pytest.fixture
    def test_agent(self):
        """Create test agent."""
        return Agent(
            id=UUID("00000000-0000-0000-0000-000000000001"),
            name="test_agent",
            display_name="Test Agent",
            agent_type="general",
            graph_definition={"nodes": [], "edges": [], "entry_point": "input"},
            is_active=True,
            created_by=UUID("00000000-0000-0000-0000-000000000003"),
            tenant_id=UUID("00000000-0000-0000-0000-000000000004")
        )
    
    @pytest.mark.asyncio
    async def test_create_agent_success(self, manager, mock_uow):
        """Test successful agent creation."""
        # Mock repository methods
        mock_uow.agents.get_by_name.return_value = None  # Name available
        mock_uow.agents.create.return_value = Agent(
            id=UUID("00000000-0000-0000-0000-000000000001"),
            name="new_agent",
            display_name="New Agent",
            agent_type="general",
            graph_definition={},
            created_by=UUID("00000000-0000-0000-0000-000000000003"),
            tenant_id=UUID("00000000-0000-0000-0000-000000000004")
        )
        
        agent = await manager.create_agent(
            uow=mock_uow,
            name="new_agent",
            display_name="New Agent",
            agent_type="general",
            graph_definition={"nodes": [], "edges": [], "entry_point": "input"},
            created_by=UUID("00000000-0000-0000-0000-000000000003"),
            tenant_id=UUID("00000000-0000-0000-0000-000000000004")
        )
        
        assert agent.name == "new_agent"
        assert agent.display_name == "New Agent"
        mock_uow.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_agent_name_taken(self, manager, mock_uow):
        """Test agent creation with taken name."""
        # Mock name already exists
        mock_uow.agents.get_by_name.return_value = MagicMock()
        
        with pytest.raises(ValidationError, match="already exists"):
            await manager.create_agent(
                uow=mock_uow,
                name="taken_name",
                display_name="Test Agent",
                agent_type="general",
                graph_definition={},
                created_by=UUID("00000000-0000-0000-0000-000000000003"),
                tenant_id=UUID("00000000-0000-0000-0000-000000000004")
            )
        
        mock_uow.rollback.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_agent_invalid_definition(self, manager, mock_loader, mock_uow):
        """Test agent creation with invalid graph definition."""
        # Mock validation errors
        mock_loader.validate_agent_definition.return_value = ["Invalid node type"]
        
        with pytest.raises(ValidationError, match="Invalid graph definition"):
            await manager.create_agent(
                uow=mock_uow,
                name="test_agent",
                display_name="Test Agent",
                agent_type="general",
                graph_definition={"invalid": "definition"},
                created_by=UUID("00000000-0000-0000-0000-000000000003"),
                tenant_id=UUID("00000000-0000-0000-0000-000000000004")
            )
    
    @pytest.mark.asyncio
    async def test_update_agent_success(self, manager, mock_uow, test_agent):
        """Test successful agent update."""
        # Mock repository methods
        mock_uow.agents.get.return_value = test_agent
        mock_uow.agents.update.return_value = test_agent
        
        # Patch permission check
        with patch.object(manager, "_can_modify_agent", return_value=True):
            updated = await manager.update_agent(
                uow=mock_uow,
                agent_id=test_agent.id,
                updated_by=test_agent.created_by,
                display_name="Updated Agent",
                description="Updated description"
            )
            
            assert updated == test_agent
            mock_uow.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_update_agent_not_found(self, manager, mock_uow):
        """Test updating nonexistent agent."""
        mock_uow.agents.get.return_value = None
        
        with pytest.raises(AgentNotFoundError):
            await manager.update_agent(
                uow=mock_uow,
                agent_id=UUID("00000000-0000-0000-0000-000000000999"),
                updated_by=UUID("00000000-0000-0000-0000-000000000003"),
                display_name="Updated"
            )
    
    @pytest.mark.asyncio
    async def test_update_agent_permission_denied(self, manager, mock_uow, test_agent):
        """Test updating agent without permission."""
        mock_uow.agents.get.return_value = test_agent
        
        # Patch permission check to deny
        with patch.object(manager, "_can_modify_agent", return_value=False):
            with pytest.raises(InsufficientPermissionsError):
                await manager.update_agent(
                    uow=mock_uow,
                    agent_id=test_agent.id,
                    updated_by=UUID("00000000-0000-0000-0000-000000000999"),
                    display_name="Updated"
                )
    
    @pytest.mark.asyncio
    async def test_delete_agent_success(self, manager, mock_uow, test_agent):
        """Test successful agent deletion."""
        mock_uow.agents.get.return_value = test_agent
        
        with patch.object(manager, "_can_modify_agent", return_value=True):
            result = await manager.delete_agent(
                uow=mock_uow,
                agent_id=test_agent.id,
                deleted_by=test_agent.created_by
            )
            
            assert result is True
            mock_uow.agents.delete.assert_called_once_with(test_agent.id)
            mock_uow.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete_system_agent(self, manager, mock_uow, test_agent):
        """Test deleting system agent fails."""
        test_agent.is_system = True
        mock_uow.agents.get.return_value = test_agent
        
        with patch.object(manager, "_can_modify_agent", return_value=True):
            with pytest.raises(ValidationError, match="Cannot delete system agents"):
                await manager.delete_agent(
                    uow=mock_uow,
                    agent_id=test_agent.id,
                    deleted_by=test_agent.created_by
                )
    
    @pytest.mark.asyncio
    async def test_get_agent_with_access_control(self, manager, mock_uow, test_agent):
        """Test getting agent with access control."""
        mock_uow.agents.get.return_value = test_agent
        
        with patch.object(manager, "_can_access_agent", return_value=True):
            agent = await manager.get_agent(
                uow=mock_uow,
                agent_id=test_agent.id,
                user_id=UUID("00000000-0000-0000-0000-000000000003")
            )
            
            assert agent == test_agent
    
    @pytest.mark.asyncio
    async def test_get_agent_access_denied(self, manager, mock_uow, test_agent):
        """Test getting agent with access denied."""
        mock_uow.agents.get.return_value = test_agent
        
        with patch.object(manager, "_can_access_agent", return_value=False):
            with pytest.raises(InsufficientPermissionsError):
                await manager.get_agent(
                    uow=mock_uow,
                    agent_id=test_agent.id,
                    user_id=UUID("00000000-0000-0000-0000-000000000999")
                )
    
    @pytest.mark.asyncio
    async def test_list_agents(self, manager, mock_uow):
        """Test listing agents with filtering."""
        # Create test agents
        agents = [
            Agent(
                id=UUID(f"00000000-0000-0000-0000-00000000000{i}"),
                name=f"agent_{i}",
                display_name=f"Agent {i}",
                agent_type="general",
                graph_definition={},
                is_active=True,
                is_public=i % 2 == 0,  # Even ones are public
                created_by=UUID("00000000-0000-0000-0000-000000000003"),
                tenant_id=UUID("00000000-0000-0000-0000-000000000004")
            )
            for i in range(1, 4)
        ]
        
        mock_uow.agents.get_multi.return_value = agents
        
        # Mock access control to allow public agents only
        async def mock_can_access(uow, agent, user_id, include_team):
            return agent.is_public
        
        with patch.object(manager, "_can_access_agent", side_effect=mock_can_access):
            result = await manager.list_agents(
                uow=mock_uow,
                user_id=UUID("00000000-0000-0000-0000-000000000003"),
                tenant_id=UUID("00000000-0000-0000-0000-000000000004")
            )
            
            # Only public agents should be returned
            assert len(result) == 1
            assert result[0].name == "agent_2"
    
    @pytest.mark.asyncio
    async def test_add_agent_memory(self, manager, mock_uow, test_agent):
        """Test adding memory to agent."""
        mock_uow.agents.get.return_value = test_agent
        
        memory = await manager.add_agent_memory(
            uow=mock_uow,
            agent_id=test_agent.id,
            memory_type="learning",
            content="Test memory content",
            user_id=UUID("00000000-0000-0000-0000-000000000003"),
            confidence=0.8
        )
        
        assert isinstance(memory, AgentMemory)
        mock_uow.session.add.assert_called_once()
        mock_uow.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_default_agents(self, manager, mock_uow):
        """Test creating default system agents."""
        # Mock successful agent creation
        created_agents = []
        
        async def mock_create_agent(uow, **kwargs):
            agent = Agent(
                id=UUID("00000000-0000-0000-0000-000000000001"),
                name=kwargs["name"],
                display_name=kwargs["display_name"],
                agent_type=kwargs["agent_type"],
                graph_definition=kwargs["graph_definition"],
                created_by=kwargs["created_by"],
                tenant_id=kwargs["tenant_id"]
            )
            created_agents.append(agent)
            return agent
        
        with patch.object(manager, "create_agent", side_effect=mock_create_agent):
            agents = await manager.create_default_agents(
                uow=mock_uow,
                tenant_id=UUID("00000000-0000-0000-0000-000000000004"),
                created_by=UUID("00000000-0000-0000-0000-000000000003")
            )
            
            assert len(agents) > 0
            assert all(isinstance(agent, Agent) for agent in agents)