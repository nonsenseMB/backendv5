"""
Tests for agent executor functionality.
"""
import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import pytest

from src.agents.context import ExecutionContext
from src.agents.events import AgentEvent, AgentEventType
from src.agents.exceptions import (
    AgentExecutionError,
    RateLimitExceededError
)
from src.agents.executor import AgentExecutor, StreamingResponse
from src.agents.loader import AgentLoader
from src.core.auth.exceptions import InsufficientPermissionsError
from src.infrastructure.database.models.agent import Agent
from src.infrastructure.database.models.conversation import Conversation
from src.infrastructure.database.models.user import User


class TestStreamingResponse:
    """Test streaming response functionality."""
    
    @pytest.mark.asyncio
    async def test_collect_all_events(self):
        """Test collecting all events from stream."""
        # Create test events
        events = [
            AgentEvent(
                event_type=AgentEventType.AGENT_START,
                timestamp=datetime.utcnow(),
                agent_id=UUID("00000000-0000-0000-0000-000000000001"),
                conversation_id=UUID("00000000-0000-0000-0000-000000000002"),
                user_id=UUID("00000000-0000-0000-0000-000000000003"),
                tenant_id=UUID("00000000-0000-0000-0000-000000000004"),
                metadata={}
            ),
            AgentEvent(
                event_type=AgentEventType.AGENT_COMPLETE,
                timestamp=datetime.utcnow(),
                agent_id=UUID("00000000-0000-0000-0000-000000000001"),
                conversation_id=UUID("00000000-0000-0000-0000-000000000002"),
                user_id=UUID("00000000-0000-0000-0000-000000000003"),
                tenant_id=UUID("00000000-0000-0000-0000-000000000004"),
                metadata={"final_output": "Test output"}
            )
        ]
        
        async def event_generator():
            for event in events:
                yield event
        
        response = StreamingResponse("test-exec-id", event_generator())
        collected = await response.collect_all()
        
        assert len(collected) == 2
        assert collected[0].event_type == AgentEventType.AGENT_START
        assert collected[1].event_type == AgentEventType.AGENT_COMPLETE
    
    @pytest.mark.asyncio
    async def test_get_final_output(self):
        """Test getting final output from stream."""
        async def event_generator():
            yield AgentEvent(
                event_type=AgentEventType.AGENT_COMPLETE,
                timestamp=datetime.utcnow(),
                agent_id=UUID("00000000-0000-0000-0000-000000000001"),
                conversation_id=UUID("00000000-0000-0000-0000-000000000002"),
                user_id=UUID("00000000-0000-0000-0000-000000000003"),
                tenant_id=UUID("00000000-0000-0000-0000-000000000004"),
                metadata={"final_output": "Test output"}
            )
        
        response = StreamingResponse("test-exec-id", event_generator())
        output = await response.get_final_output()
        
        assert output == "Test output"
    
    @pytest.mark.asyncio
    async def test_get_final_output_with_error(self):
        """Test getting final output when error occurs."""
        async def event_generator():
            yield AgentEvent(
                event_type=AgentEventType.AGENT_ERROR,
                timestamp=datetime.utcnow(),
                agent_id=UUID("00000000-0000-0000-0000-000000000001"),
                conversation_id=UUID("00000000-0000-0000-0000-000000000002"),
                user_id=UUID("00000000-0000-0000-0000-000000000003"),
                tenant_id=UUID("00000000-0000-0000-0000-000000000004"),
                metadata={"error_message": "Test error"}
            )
        
        response = StreamingResponse("test-exec-id", event_generator())
        
        with pytest.raises(AgentExecutionError):
            await response.get_final_output()


class TestAgentExecutor:
    """Test agent executor functionality."""
    
    @pytest.fixture
    def mock_loader(self):
        """Mock agent loader."""
        loader = MagicMock(spec=AgentLoader)
        return loader
    
    @pytest.fixture
    def executor(self, mock_loader):
        """Create agent executor with mocked dependencies."""
        return AgentExecutor(loader=mock_loader)
    
    @pytest.fixture
    def test_agent(self):
        """Create test agent."""
        return Agent(
            id=UUID("00000000-0000-0000-0000-000000000001"),
            name="test_agent",
            display_name="Test Agent",
            agent_type="general",
            graph_definition={},
            is_public=True,
            is_active=True,
            created_by=UUID("00000000-0000-0000-0000-000000000003"),
            tenant_id=UUID("00000000-0000-0000-0000-000000000004")
        )
    
    @pytest.fixture
    def test_user(self):
        """Create test user."""
        return User(
            id=UUID("00000000-0000-0000-0000-000000000003"),
            email="test@example.com",
            tenant_id=UUID("00000000-0000-0000-0000-000000000004")
        )
    
    @pytest.fixture
    def test_conversation(self):
        """Create test conversation."""
        return Conversation(
            id=UUID("00000000-0000-0000-0000-000000000002"),
            user_id=UUID("00000000-0000-0000-0000-000000000003"),
            tenant_id=UUID("00000000-0000-0000-0000-000000000004")
        )
    
    @pytest.mark.asyncio
    async def test_execute_success(self, executor, mock_loader, test_agent, test_user, test_conversation):
        """Test successful agent execution."""
        # Mock graph
        mock_graph = AsyncMock()
        mock_graph.ainvoke = AsyncMock(return_value=MagicMock())
        mock_loader.load_agent.return_value = mock_graph
        
        # Execute
        with patch("src.agents.executor.context_manager") as mock_context_manager:
            mock_context = MagicMock(spec=ExecutionContext)
            mock_context_manager.create_context.return_value = mock_context
            
            response = await executor.execute(
                agent=test_agent,
                user=test_user,
                conversation=test_conversation,
                message="Test message",
                stream=False
            )
            
            assert isinstance(response, StreamingResponse)
            assert response.execution_id is not None
    
    @pytest.mark.asyncio
    async def test_execute_permission_denied(self, executor, test_agent, test_user, test_conversation):
        """Test execution with permission denied."""
        # Make agent private
        test_agent.is_public = False
        test_agent.created_by = UUID("00000000-0000-0000-0000-000000000999")
        test_agent.allowed_roles = ["admin"]
        
        with pytest.raises(InsufficientPermissionsError):
            await executor.execute(
                agent=test_agent,
                user=test_user,
                conversation=test_conversation,
                message="Test message"
            )
    
    @pytest.mark.asyncio
    async def test_execute_rate_limit_exceeded(self, executor, test_agent, test_user, test_conversation):
        """Test execution with rate limit exceeded."""
        with patch("src.agents.executor.context_manager") as mock_context_manager:
            mock_context = MagicMock(spec=ExecutionContext)
            mock_context.check_rate_limit.return_value = False
            mock_context_manager.create_context.return_value = mock_context
            
            with pytest.raises(RateLimitExceededError):
                await executor.execute(
                    agent=test_agent,
                    user=test_user,
                    conversation=test_conversation,
                    message="Test message"
                )
    
    @pytest.mark.asyncio
    async def test_cancel_execution(self, executor):
        """Test canceling an active execution."""
        # Add active execution
        mock_context = MagicMock(spec=ExecutionContext)
        execution_id = "test-exec-id"
        executor.active_executions[execution_id] = mock_context
        
        with patch("src.agents.executor.context_manager") as mock_context_manager:
            result = await executor.cancel_execution(execution_id)
            
            assert result is True
            assert execution_id not in executor.active_executions
            mock_context_manager.remove_context.assert_called_once_with(execution_id)
    
    @pytest.mark.asyncio
    async def test_cancel_nonexistent_execution(self, executor):
        """Test canceling a nonexistent execution."""
        result = await executor.cancel_execution("nonexistent-id")
        assert result is False
    
    def test_get_active_executions(self, executor):
        """Test getting list of active executions."""
        # Add some active executions
        mock_context1 = MagicMock(spec=ExecutionContext)
        mock_context1.agent.id = UUID("00000000-0000-0000-0000-000000000001")
        mock_context1.agent.name = "agent1"
        mock_context1.user.id = UUID("00000000-0000-0000-0000-000000000003")
        mock_context1.started_at = datetime.utcnow()
        
        mock_context2 = MagicMock(spec=ExecutionContext)
        mock_context2.agent.id = UUID("00000000-0000-0000-0000-000000000002")
        mock_context2.agent.name = "agent2"
        mock_context2.user.id = UUID("00000000-0000-0000-0000-000000000003")
        mock_context2.started_at = datetime.utcnow()
        
        executor.active_executions = {
            "exec1": mock_context1,
            "exec2": mock_context2
        }
        
        active = executor.get_active_executions()
        
        assert len(active) == 2
        assert active[0]["execution_id"] == "exec1"
        assert active[0]["agent_name"] == "agent1"
        assert active[1]["execution_id"] == "exec2"
        assert active[1]["agent_name"] == "agent2"