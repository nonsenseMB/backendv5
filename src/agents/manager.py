"""
Agent manager with access control and lifecycle management.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.executor import AgentExecutor, StreamingResponse
from src.agents.loader import AgentLoader, create_default_agent_definitions
from src.agents.exceptions import (
    AgentNotFoundError,
    ValidationError
)
from src.core.auth.exceptions import InsufficientPermissionsError
from src.core.logging import get_logger
from src.infrastructure.database.models.agent import Agent, AgentMemory, AgentTool
from src.infrastructure.database.models.conversation import Conversation
from src.infrastructure.database.models.user import User
from src.infrastructure.database.repositories.agent import AgentRepository
from src.infrastructure.database.uow import UnitOfWork

logger = get_logger(__name__)


class AgentManager:
    """Manager for agent lifecycle and access control."""
    
    def __init__(
        self,
        loader: AgentLoader,
        executor: AgentExecutor,
        default_llm_provider: Any = None
    ):
        self.loader = loader
        self.executor = executor
        self.default_llm_provider = default_llm_provider
    
    async def create_agent(
        self,
        uow: UnitOfWork,
        name: str,
        display_name: str,
        agent_type: str,
        graph_definition: Dict[str, Any],
        created_by: UUID,
        tenant_id: UUID,
        description: Optional[str] = None,
        specialization: Optional[str] = None,
        system_prompt: Optional[str] = None,
        capabilities: List[str] = None,
        tool_ids: List[UUID] = None,
        is_public: bool = False,
        team_id: Optional[UUID] = None
    ) -> Agent:
        """Create a new agent."""
        async with uow:
            try:
                # Validate graph definition
                errors = self.loader.validate_agent_definition(graph_definition)
                if errors:
                    raise ValidationError(f"Invalid graph definition: {', '.join(errors)}")
                
                # Check if name is available
                existing = await uow.agents.get_by_name(name)
                if existing:
                    raise ValidationError(f"Agent name '{name}' already exists")
                
                # Create agent
                agent = Agent(
                    name=name,
                    display_name=display_name,
                    description=description,
                    agent_type=agent_type,
                    specialization=specialization,
                    graph_definition=graph_definition,
                    system_prompt=system_prompt or self._get_default_system_prompt(agent_type),
                    capabilities=capabilities or [],
                    tool_ids=tool_ids or [],
                    is_public=is_public,
                    created_by=created_by,
                    tenant_id=tenant_id,
                    team_id=team_id,
                    is_active=True
                )
                
                agent = await uow.agents.create(agent)
                
                # Create tool associations if provided
                if tool_ids:
                    for tool_id in tool_ids:
                        agent_tool = AgentTool(
                            agent_id=agent.id,
                            tool_id=tool_id,
                            is_enabled=True
                        )
                        await uow.session.add(agent_tool)
                
                await uow.commit()
                
                logger.info(
                    "Created agent",
                    agent_id=str(agent.id),
                    agent_name=name,
                    agent_type=agent_type,
                    created_by=str(created_by)
                )
                
                return agent
                
            except Exception as e:
                await uow.rollback()
                logger.error(f"Failed to create agent: {str(e)}")
                raise
    
    async def update_agent(
        self,
        uow: UnitOfWork,
        agent_id: UUID,
        updated_by: UUID,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        graph_definition: Optional[Dict[str, Any]] = None,
        system_prompt: Optional[str] = None,
        capabilities: Optional[List[str]] = None,
        tool_ids: Optional[List[UUID]] = None,
        is_active: Optional[bool] = None,
        is_public: Optional[bool] = None
    ) -> Agent:
        """Update an agent."""
        async with uow:
            try:
                # Get agent
                agent = await uow.agents.get(agent_id)
                if not agent:
                    raise AgentNotFoundError(f"Agent {agent_id} not found")
                
                # Check permissions
                if not await self._can_modify_agent(uow, agent, updated_by):
                    raise InsufficientPermissionsError(
                        f"User {updated_by} cannot modify agent {agent_id}"
                    )
                
                # Validate graph definition if provided
                if graph_definition:
                    errors = self.loader.validate_agent_definition(graph_definition)
                    if errors:
                        raise ValidationError(f"Invalid graph definition: {', '.join(errors)}")
                
                # Update fields
                update_data = {}
                if display_name is not None:
                    update_data["display_name"] = display_name
                if description is not None:
                    update_data["description"] = description
                if graph_definition is not None:
                    update_data["graph_definition"] = graph_definition
                if system_prompt is not None:
                    update_data["system_prompt"] = system_prompt
                if capabilities is not None:
                    update_data["capabilities"] = capabilities
                if tool_ids is not None:
                    update_data["tool_ids"] = tool_ids
                if is_active is not None:
                    update_data["is_active"] = is_active
                if is_public is not None:
                    update_data["is_public"] = is_public
                
                # Update agent
                agent = await uow.agents.update(agent_id, **update_data)
                
                # Update tool associations if provided
                if tool_ids is not None:
                    # Remove existing associations
                    await uow.session.execute(
                        f"DELETE FROM agent_tools WHERE agent_id = '{agent_id}'"
                    )
                    
                    # Create new associations
                    for tool_id in tool_ids:
                        agent_tool = AgentTool(
                            agent_id=agent_id,
                            tool_id=tool_id,
                            is_enabled=True
                        )
                        await uow.session.add(agent_tool)
                
                await uow.commit()
                
                logger.info(
                    "Updated agent",
                    agent_id=str(agent_id),
                    updated_by=str(updated_by),
                    fields_updated=list(update_data.keys())
                )
                
                return agent
                
            except Exception as e:
                await uow.rollback()
                logger.error(f"Failed to update agent: {str(e)}")
                raise
    
    async def delete_agent(
        self,
        uow: UnitOfWork,
        agent_id: UUID,
        deleted_by: UUID
    ) -> bool:
        """Delete an agent."""
        async with uow:
            try:
                # Get agent
                agent = await uow.agents.get(agent_id)
                if not agent:
                    raise AgentNotFoundError(f"Agent {agent_id} not found")
                
                # Check permissions
                if not await self._can_modify_agent(uow, agent, deleted_by):
                    raise InsufficientPermissionsError(
                        f"User {deleted_by} cannot delete agent {agent_id}"
                    )
                
                # Check if agent is system agent
                if hasattr(agent, "is_system") and agent.is_system:
                    raise ValidationError("Cannot delete system agents")
                
                # Delete agent (cascade will handle related records)
                await uow.agents.delete(agent_id)
                await uow.commit()
                
                logger.info(
                    "Deleted agent",
                    agent_id=str(agent_id),
                    deleted_by=str(deleted_by)
                )
                
                return True
                
            except Exception as e:
                await uow.rollback()
                logger.error(f"Failed to delete agent: {str(e)}")
                raise
    
    async def get_agent(
        self,
        uow: UnitOfWork,
        agent_id: UUID,
        user_id: UUID
    ) -> Agent:
        """Get an agent with access control."""
        async with uow:
            # Get agent
            agent = await uow.agents.get(agent_id)
            if not agent:
                raise AgentNotFoundError(f"Agent {agent_id} not found")
            
            # Check access
            if not await self._can_access_agent(uow, agent, user_id):
                raise InsufficientPermissionsError(
                    f"User {user_id} cannot access agent {agent_id}"
                )
            
            return agent
    
    async def list_agents(
        self,
        uow: UnitOfWork,
        user_id: UUID,
        tenant_id: UUID,
        include_inactive: bool = False,
        include_team_agents: bool = True,
        limit: int = 100,
        offset: int = 0
    ) -> List[Agent]:
        """List agents accessible to user."""
        async with uow:
            # Get all agents for tenant
            filters = {"tenant_id": tenant_id}
            if not include_inactive:
                filters["is_active"] = True
            
            agents = await uow.agents.get_multi(
                skip=offset,
                limit=limit,
                filters=filters,
                order_by="name"
            )
            
            # Filter by access
            accessible_agents = []
            for agent in agents:
                if await self._can_access_agent(uow, agent, user_id, include_team_agents):
                    accessible_agents.append(agent)
            
            return accessible_agents
    
    async def execute_agent(
        self,
        uow: UnitOfWork,
        agent_id: UUID,
        user: User,
        conversation: Conversation,
        message: str,
        context: Optional[Dict[str, Any]] = None,
        stream: bool = True
    ) -> StreamingResponse:
        """Execute an agent."""
        async with uow:
            # Get agent
            agent = await self.get_agent(uow, agent_id, user.id)
            
            # Check if agent is active
            if not agent.is_active:
                raise ValidationError(f"Agent {agent_id} is not active")
            
            # Add user roles to context
            if context is None:
                context = {}
            context["user_roles"] = await self._get_user_roles(uow, user.id)
            
            # Execute agent
            response = await self.executor.execute(
                agent=agent,
                user=user,
                conversation=conversation,
                message=message,
                context=context,
                stream=stream
            )
            
            # Update agent metrics
            agent.total_conversations += 1
            await uow.commit()
            
            return response
    
    async def create_default_agents(
        self,
        uow: UnitOfWork,
        tenant_id: UUID,
        created_by: UUID
    ) -> List[Agent]:
        """Create default system agents for a tenant."""
        default_definitions = create_default_agent_definitions()
        created_agents = []
        
        for agent_key, definition in default_definitions.items():
            try:
                # Determine agent properties based on key
                if agent_key == "qa_agent":
                    name = f"qa_agent_{tenant_id}"
                    display_name = "Q&A Assistant"
                    agent_type = "general"
                    description = "General question and answer assistant"
                elif agent_key == "tool_agent":
                    name = f"tool_agent_{tenant_id}"
                    display_name = "Tool-Using Assistant"
                    agent_type = "specialist"
                    description = "Assistant that can use tools to help with tasks"
                    specialization = "tools"
                else:
                    continue
                
                # Create agent
                agent = await self.create_agent(
                    uow=uow,
                    name=name,
                    display_name=display_name,
                    agent_type=agent_type,
                    graph_definition=definition,
                    created_by=created_by,
                    tenant_id=tenant_id,
                    description=description,
                    specialization=specialization if "specialization" in locals() else None,
                    capabilities=["conversation", "memory"],
                    is_public=True
                )
                
                created_agents.append(agent)
                
            except Exception as e:
                logger.error(f"Failed to create default agent {agent_key}: {str(e)}")
        
        return created_agents
    
    async def add_agent_memory(
        self,
        uow: UnitOfWork,
        agent_id: UUID,
        memory_type: str,
        content: str,
        user_id: Optional[UUID] = None,
        conversation_id: Optional[UUID] = None,
        confidence: float = 0.5,
        source: str = "user_feedback"
    ) -> AgentMemory:
        """Add a memory to an agent."""
        async with uow:
            try:
                # Get agent to verify it exists
                agent = await uow.agents.get(agent_id)
                if not agent:
                    raise AgentNotFoundError(f"Agent {agent_id} not found")
                
                # Create memory
                memory = AgentMemory(
                    agent_id=agent_id,
                    tenant_id=agent.tenant_id,
                    user_id=user_id,
                    conversation_id=conversation_id,
                    memory_type=memory_type,
                    content=content,
                    confidence=confidence,
                    source=source,
                    is_active=True
                )
                
                await uow.session.add(memory)
                await uow.commit()
                
                logger.info(
                    "Added agent memory",
                    agent_id=str(agent_id),
                    memory_type=memory_type,
                    source=source
                )
                
                return memory
                
            except Exception as e:
                await uow.rollback()
                logger.error(f"Failed to add agent memory: {str(e)}")
                raise
    
    async def get_agent_memories(
        self,
        uow: UnitOfWork,
        agent_id: UUID,
        memory_type: Optional[str] = None,
        user_id: Optional[UUID] = None,
        limit: int = 100
    ) -> List[AgentMemory]:
        """Get memories for an agent."""
        async with uow:
            # Build query
            query = uow.session.query(AgentMemory).filter(
                AgentMemory.agent_id == agent_id,
                AgentMemory.is_active == True
            )
            
            if memory_type:
                query = query.filter(AgentMemory.memory_type == memory_type)
            
            if user_id:
                query = query.filter(AgentMemory.user_id == user_id)
            
            # Order by confidence and recency
            query = query.order_by(
                AgentMemory.confidence.desc(),
                AgentMemory.created_at.desc()
            ).limit(limit)
            
            result = await uow.session.execute(query)
            return result.scalars().all()
    
    async def _can_access_agent(
        self,
        uow: UnitOfWork,
        agent: Agent,
        user_id: UUID,
        include_team_agents: bool = True
    ) -> bool:
        """Check if user can access an agent."""
        # Public agents are accessible to all
        if agent.is_public:
            return True
        
        # Creator can always access
        if agent.created_by == user_id:
            return True
        
        # Check team membership if agent belongs to a team
        if include_team_agents and agent.team_id:
            # This would check team membership in the database
            # For now, we'll assume the check is implemented elsewhere
            pass
        
        # Check user roles against allowed roles
        user_roles = await self._get_user_roles(uow, user_id)
        if any(role in agent.allowed_roles for role in user_roles):
            return True
        
        return False
    
    async def _can_modify_agent(
        self,
        uow: UnitOfWork,
        agent: Agent,
        user_id: UUID
    ) -> bool:
        """Check if user can modify an agent."""
        # Only creator and admins can modify
        if agent.created_by == user_id:
            return True
        
        # Check if user is admin
        user_roles = await self._get_user_roles(uow, user_id)
        if "admin" in user_roles:
            return True
        
        return False
    
    async def _get_user_roles(
        self,
        uow: UnitOfWork,
        user_id: UUID
    ) -> List[str]:
        """Get user roles."""
        # This would typically query the user's roles from the database
        # For now, return a default set
        return ["member"]
    
    def _get_default_system_prompt(self, agent_type: str) -> str:
        """Get default system prompt for agent type."""
        prompts = {
            "general": "You are a helpful AI assistant. Provide clear, accurate, and helpful responses.",
            "specialist": "You are a specialized AI assistant with expertise in your domain. Provide detailed and accurate information.",
            "coordinator": "You are a coordination agent that helps manage tasks and delegate to other agents.",
            "team": "You are a team agent that represents a collaborative workspace. Help coordinate team activities."
        }
        return prompts.get(agent_type, prompts["general"])