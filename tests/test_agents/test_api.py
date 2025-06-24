"""
Tests for agent API endpoints.
"""
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from src.agents.exceptions import (
    AgentExecutionError,
    AgentNotFoundError,
    ValidationError
)
from src.core.auth.exceptions import InsufficientPermissionsError
from src.infrastructure.database.models.agent import Agent, AgentMemory
from src.infrastructure.database.models.user import User


class TestAgentAPI:
    """Test agent API endpoints."""
    
    @pytest.fixture
    def test_user(self):
        """Create test user."""
        return User(
            id=UUID("00000000-0000-0000-0000-000000000003"),
            email="test@example.com",
            tenant_id=UUID("00000000-0000-0000-0000-000000000004"),
            role="member"
        )
    
    @pytest.fixture
    def test_agent(self):
        """Create test agent."""
        return Agent(
            id=UUID("00000000-0000-0000-0000-000000000001"),
            name="test_agent",
            display_name="Test Agent",
            description="Test description",
            agent_type="general",
            graph_definition={"nodes": [], "edges": [], "entry_point": "input"},
            capabilities=["conversation"],
            tool_ids=[],
            is_public=True,
            is_active=True,
            created_by=UUID("00000000-0000-0000-0000-000000000003"),
            tenant_id=UUID("00000000-0000-0000-0000-000000000004"),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            total_conversations=10,
            satisfaction_score=4.5,
            avg_response_time_ms=250
        )
    
    @pytest.mark.asyncio
    async def test_create_agent(self, client: TestClient, test_user, test_agent):
        """Test creating an agent."""
        with patch("src.api.v1.agents.router.get_current_user", return_value=test_user):
            with patch("src.api.v1.agents.router.agent_manager.create_agent", return_value=test_agent):
                response = client.post(
                    "/api/v1/agents",
                    json={
                        "name": "test_agent",
                        "display_name": "Test Agent",
                        "description": "Test description",
                        "agent_type": "general",
                        "graph_definition": {
                            "nodes": [],
                            "edges": [],
                            "entry_point": "input"
                        }
                    }
                )
                
                assert response.status_code == status.HTTP_201_CREATED
                data = response.json()
                assert data["name"] == "test_agent"
                assert data["display_name"] == "Test Agent"
    
    @pytest.mark.asyncio
    async def test_create_agent_validation_error(self, client: TestClient, test_user):
        """Test creating agent with validation error."""
        with patch("src.api.v1.agents.router.get_current_user", return_value=test_user):
            with patch("src.api.v1.agents.router.agent_manager.create_agent", 
                      side_effect=ValidationError("Invalid name")):
                response = client.post(
                    "/api/v1/agents",
                    json={
                        "name": "invalid name!",
                        "display_name": "Test Agent",
                        "agent_type": "general",
                        "graph_definition": {}
                    }
                )
                
                assert response.status_code == status.HTTP_400_BAD_REQUEST
                assert "Invalid name" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_list_agents(self, client: TestClient, test_user, test_agent):
        """Test listing agents."""
        agents = [test_agent]
        
        with patch("src.api.v1.agents.router.get_current_user", return_value=test_user):
            with patch("src.api.v1.agents.router.agent_manager.list_agents", return_value=agents):
                response = client.get("/api/v1/agents")
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert data["total"] == 1
                assert len(data["agents"]) == 1
                assert data["agents"][0]["name"] == "test_agent"
    
    @pytest.mark.asyncio
    async def test_get_agent(self, client: TestClient, test_user, test_agent):
        """Test getting agent details."""
        with patch("src.api.v1.agents.router.get_current_user", return_value=test_user):
            with patch("src.api.v1.agents.router.agent_manager.get_agent", return_value=test_agent):
                response = client.get(f"/api/v1/agents/{test_agent.id}")
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert data["id"] == str(test_agent.id)
                assert data["name"] == "test_agent"
                assert "graph_definition" in data
    
    @pytest.mark.asyncio
    async def test_get_agent_not_found(self, client: TestClient, test_user):
        """Test getting nonexistent agent."""
        agent_id = UUID("00000000-0000-0000-0000-000000000999")
        
        with patch("src.api.v1.agents.router.get_current_user", return_value=test_user):
            with patch("src.api.v1.agents.router.agent_manager.get_agent", 
                      side_effect=AgentNotFoundError()):
                response = client.get(f"/api/v1/agents/{agent_id}")
                
                assert response.status_code == status.HTTP_404_NOT_FOUND
    
    @pytest.mark.asyncio
    async def test_update_agent(self, client: TestClient, test_user, test_agent):
        """Test updating an agent."""
        test_agent.display_name = "Updated Agent"
        
        with patch("src.api.v1.agents.router.get_current_user", return_value=test_user):
            with patch("src.api.v1.agents.router.agent_manager.update_agent", return_value=test_agent):
                response = client.patch(
                    f"/api/v1/agents/{test_agent.id}",
                    json={
                        "display_name": "Updated Agent",
                        "description": "Updated description"
                    }
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert data["display_name"] == "Updated Agent"
    
    @pytest.mark.asyncio
    async def test_update_agent_permission_denied(self, client: TestClient, test_user):
        """Test updating agent without permission."""
        agent_id = UUID("00000000-0000-0000-0000-000000000001")
        
        with patch("src.api.v1.agents.router.get_current_user", return_value=test_user):
            with patch("src.api.v1.agents.router.agent_manager.update_agent", 
                      side_effect=InsufficientPermissionsError()):
                response = client.patch(
                    f"/api/v1/agents/{agent_id}",
                    json={"display_name": "Updated"}
                )
                
                assert response.status_code == status.HTTP_403_FORBIDDEN
    
    @pytest.mark.asyncio
    async def test_delete_agent(self, client: TestClient, test_user):
        """Test deleting an agent."""
        agent_id = UUID("00000000-0000-0000-0000-000000000001")
        
        with patch("src.api.v1.agents.router.get_current_user", return_value=test_user):
            with patch("src.api.v1.agents.router.agent_manager.delete_agent", return_value=True):
                response = client.delete(f"/api/v1/agents/{agent_id}")
                
                assert response.status_code == status.HTTP_204_NO_CONTENT
    
    @pytest.mark.asyncio
    async def test_execute_agent_non_streaming(self, client: TestClient, test_user):
        """Test executing agent without streaming."""
        agent_id = UUID("00000000-0000-0000-0000-000000000001")
        
        # Mock streaming response
        mock_response = MagicMock()
        mock_response.execution_id = "test-exec-id"
        mock_response.final_output = "Test output"
        mock_response.events = AsyncMock()
        
        with patch("src.api.v1.agents.router.get_current_user", return_value=test_user):
            with patch("src.api.v1.agents.router.agent_manager.execute_agent", return_value=mock_response):
                response = client.post(
                    f"/api/v1/agents/{agent_id}/execute",
                    json={
                        "message": "Test message",
                        "stream": False
                    }
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert data["execution_id"] == "test-exec-id"
    
    @pytest.mark.asyncio
    async def test_validate_agent_definition(self, client: TestClient, test_user):
        """Test validating agent definition."""
        with patch("src.api.v1.agents.router.get_current_user", return_value=test_user):
            with patch("src.api.v1.agents.router.agent_loader.validate_agent_definition", return_value=[]):
                response = client.post(
                    "/api/v1/agents/validate",
                    json={
                        "graph_definition": {
                            "nodes": [],
                            "edges": [],
                            "entry_point": "input"
                        }
                    }
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert data["valid"] is True
                assert len(data["errors"]) == 0
    
    @pytest.mark.asyncio
    async def test_add_agent_memory(self, client: TestClient, test_user):
        """Test adding memory to agent."""
        agent_id = UUID("00000000-0000-0000-0000-000000000001")
        
        memory = AgentMemory(
            id=UUID("00000000-0000-0000-0000-000000000002"),
            agent_id=agent_id,
            memory_type="learning",
            content="Test memory",
            confidence=0.8,
            usefulness_score=0.7,
            application_count=5,
            source="user_feedback",
            is_active=True,
            created_at=datetime.utcnow()
        )
        
        with patch("src.api.v1.agents.router.get_current_user", return_value=test_user):
            with patch("src.api.v1.agents.router.agent_manager.add_agent_memory", return_value=memory):
                response = client.post(
                    f"/api/v1/agents/{agent_id}/memories",
                    json={
                        "memory_type": "learning",
                        "content": "Test memory",
                        "confidence": 0.8,
                        "source": "user_feedback"
                    }
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert data["memory_type"] == "learning"
                assert data["content"] == "Test memory"
    
    @pytest.mark.asyncio
    async def test_create_default_agents(self, client: TestClient, test_user, test_agent):
        """Test creating default agents."""
        test_user.role = "admin"  # Must be admin
        agents = [test_agent]
        
        with patch("src.api.v1.agents.router.get_current_user", return_value=test_user):
            with patch("src.api.v1.agents.router.agent_manager.create_default_agents", return_value=agents):
                response = client.post("/api/v1/agents/default")
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert len(data) == 1
                assert data[0]["name"] == "test_agent"
    
    @pytest.mark.asyncio
    async def test_create_default_agents_non_admin(self, client: TestClient, test_user):
        """Test creating default agents as non-admin."""
        test_user.role = "member"  # Not admin
        
        with patch("src.api.v1.agents.router.get_current_user", return_value=test_user):
            response = client.post("/api/v1/agents/default")
            
            assert response.status_code == status.HTTP_403_FORBIDDEN