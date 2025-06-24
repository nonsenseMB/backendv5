"""
Agent management API endpoints.
"""
import json
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from slowapi import Limiter
from slowapi.util import get_remote_address

from src.agents import AgentExecutor, AgentLoader, AgentManager
from src.api.dependencies import get_current_user, get_uow, limiter
from src.agents.exceptions import (
    AgentExecutionError,
    AgentNotFoundError,
    RateLimitExceededError,
    ValidationError
)
from src.core.auth.exceptions import InsufficientPermissionsError
from src.infrastructure.database.models.user import User
from src.infrastructure.database.uow import UnitOfWork

from .schemas import (
    AgentCloneRequest,
    AgentCreateRequest,
    AgentDetailResponse,
    AgentEventResponse,
    AgentExecuteRequest,
    AgentExecuteResponse,
    AgentExportResponse,
    AgentImportRequest,
    AgentListResponse,
    AgentMemoryRequest,
    AgentMemoryResponse,
    AgentResponse,
    AgentUpdateRequest,
    AgentValidationRequest,
    AgentValidationResponse
)

router = APIRouter(prefix="/agents", tags=["agents"])

# Initialize agent system components
# These would typically be injected via dependency injection
agent_loader = AgentLoader(llm_provider=None)  # Will be configured with actual LLM
agent_executor = AgentExecutor(loader=agent_loader)
agent_manager = AgentManager(loader=agent_loader, executor=agent_executor)


@router.post(
    "",
    response_model=AgentResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(limiter.limit("10/hour"))]
)
async def create_agent(
    request: AgentCreateRequest,
    uow: UnitOfWork = Depends(get_uow),
    current_user: User = Depends(get_current_user)
) -> AgentResponse:
    """Create a new agent."""
    try:
        agent = await agent_manager.create_agent(
            uow=uow,
            name=request.name,
            display_name=request.display_name,
            agent_type=request.agent_type,
            graph_definition=request.graph_definition,
            created_by=current_user.id,
            tenant_id=current_user.tenant_id,
            description=request.description,
            specialization=request.specialization,
            system_prompt=request.system_prompt,
            capabilities=request.capabilities,
            tool_ids=request.tool_ids,
            is_public=request.is_public,
            team_id=request.team_id
        )
        return AgentResponse.from_orm(agent)
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create agent"
        )


@router.get("", response_model=AgentListResponse)
async def list_agents(
    include_inactive: bool = Query(False),
    include_team_agents: bool = Query(True),
    limit: int = Query(100, le=100),
    offset: int = Query(0, ge=0),
    uow: UnitOfWork = Depends(get_uow),
    current_user: User = Depends(get_current_user)
) -> AgentListResponse:
    """List agents accessible to the current user."""
    try:
        agents = await agent_manager.list_agents(
            uow=uow,
            user_id=current_user.id,
            tenant_id=current_user.tenant_id,
            include_inactive=include_inactive,
            include_team_agents=include_team_agents,
            limit=limit,
            offset=offset
        )
        
        # Get total count
        total = len(agents)  # In production, use a separate count query
        
        return AgentListResponse(
            agents=[AgentResponse.from_orm(agent) for agent in agents],
            total=total,
            limit=limit,
            offset=offset
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list agents"
        )


@router.get("/{agent_id}", response_model=AgentDetailResponse)
async def get_agent(
    agent_id: UUID,
    uow: UnitOfWork = Depends(get_uow),
    current_user: User = Depends(get_current_user)
) -> AgentDetailResponse:
    """Get agent details."""
    try:
        agent = await agent_manager.get_agent(
            uow=uow,
            agent_id=agent_id,
            user_id=current_user.id
        )
        return AgentDetailResponse.from_orm(agent)
    except AgentNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found"
        )
    except InsufficientPermissionsError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )


@router.patch(
    "/{agent_id}",
    response_model=AgentResponse,
    dependencies=[Depends(limiter.limit("20/hour"))]
)
async def update_agent(
    agent_id: UUID,
    request: AgentUpdateRequest,
    uow: UnitOfWork = Depends(get_uow),
    current_user: User = Depends(get_current_user)
) -> AgentResponse:
    """Update an agent."""
    try:
        agent = await agent_manager.update_agent(
            uow=uow,
            agent_id=agent_id,
            updated_by=current_user.id,
            display_name=request.display_name,
            description=request.description,
            graph_definition=request.graph_definition,
            system_prompt=request.system_prompt,
            capabilities=request.capabilities,
            tool_ids=request.tool_ids,
            is_active=request.is_active,
            is_public=request.is_public
        )
        return AgentResponse.from_orm(agent)
    except AgentNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found"
        )
    except InsufficientPermissionsError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot modify this agent"
        )
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.delete(
    "/{agent_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(limiter.limit("5/hour"))]
)
async def delete_agent(
    agent_id: UUID,
    uow: UnitOfWork = Depends(get_uow),
    current_user: User = Depends(get_current_user)
):
    """Delete an agent."""
    try:
        await agent_manager.delete_agent(
            uow=uow,
            agent_id=agent_id,
            deleted_by=current_user.id
        )
    except AgentNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found"
        )
    except InsufficientPermissionsError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot delete this agent"
        )
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post(
    "/{agent_id}/execute",
    response_model=AgentExecuteResponse,
    dependencies=[Depends(limiter.limit("100/hour"))]
)
async def execute_agent(
    agent_id: UUID,
    request: AgentExecuteRequest,
    uow: UnitOfWork = Depends(get_uow),
    current_user: User = Depends(get_current_user)
) -> AgentExecuteResponse:
    """Execute an agent."""
    try:
        # Get current conversation
        # In a real implementation, this would get or create a conversation
        from src.infrastructure.database.models.conversation import Conversation
        conversation = Conversation(
            id=UUID("00000000-0000-0000-0000-000000000000"),  # Placeholder
            user_id=current_user.id,
            tenant_id=current_user.tenant_id
        )
        
        # Execute agent
        response = await agent_manager.execute_agent(
            uow=uow,
            agent_id=agent_id,
            user=current_user,
            conversation=conversation,
            message=request.message,
            context=request.context,
            stream=request.stream
        )
        
        if request.stream:
            # Return streaming response
            async def event_generator():
                async for event in response.events:
                    event_data = AgentEventResponse(
                        event_type=event.event_type.value,
                        timestamp=event.timestamp,
                        agent_id=event.agent_id,
                        metadata=event.metadata,
                        content=event.metadata.get("content"),
                        token=event.metadata.get("token"),
                        error=event.metadata.get("error")
                    )
                    yield f"data: {event_data.json()}\n\n"
            
            return StreamingResponse(
                event_generator(),
                media_type="text/event-stream"
            )
        else:
            # Return execution ID for non-streaming
            return AgentExecuteResponse(
                execution_id=response.execution_id,
                status="completed" if response.final_output else "processing"
            )
    
    except AgentNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found"
        )
    except InsufficientPermissionsError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot execute this agent"
        )
    except RateLimitExceededError as e:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e)
        )
    except AgentExecutionError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Agent execution failed: {str(e)}"
        )


@router.post("/{agent_id}/memories", response_model=AgentMemoryResponse)
async def add_agent_memory(
    agent_id: UUID,
    request: AgentMemoryRequest,
    uow: UnitOfWork = Depends(get_uow),
    current_user: User = Depends(get_current_user)
) -> AgentMemoryResponse:
    """Add a memory to an agent."""
    try:
        memory = await agent_manager.add_agent_memory(
            uow=uow,
            agent_id=agent_id,
            memory_type=request.memory_type,
            content=request.content,
            user_id=current_user.id,
            conversation_id=request.conversation_id,
            confidence=request.confidence,
            source=request.source
        )
        return AgentMemoryResponse.from_orm(memory)
    except AgentNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found"
        )


@router.get("/{agent_id}/memories", response_model=List[AgentMemoryResponse])
async def get_agent_memories(
    agent_id: UUID,
    memory_type: Optional[str] = Query(None),
    limit: int = Query(100, le=100),
    uow: UnitOfWork = Depends(get_uow),
    current_user: User = Depends(get_current_user)
) -> List[AgentMemoryResponse]:
    """Get memories for an agent."""
    try:
        memories = await agent_manager.get_agent_memories(
            uow=uow,
            agent_id=agent_id,
            memory_type=memory_type,
            user_id=current_user.id,
            limit=limit
        )
        return [AgentMemoryResponse.from_orm(memory) for memory in memories]
    except AgentNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found"
        )


@router.post("/validate", response_model=AgentValidationResponse)
async def validate_agent_definition(
    request: AgentValidationRequest,
    current_user: User = Depends(get_current_user)
) -> AgentValidationResponse:
    """Validate an agent graph definition."""
    errors = agent_loader.validate_agent_definition(request.graph_definition)
    warnings = []
    
    # Add warnings for best practices
    if "metadata" not in request.graph_definition:
        warnings.append("Consider adding metadata with description and version")
    
    nodes = request.graph_definition.get("nodes", [])
    if len(nodes) > 20:
        warnings.append("Graph has many nodes, consider simplifying")
    
    return AgentValidationResponse(
        valid=len(errors) == 0,
        errors=errors,
        warnings=warnings
    )


@router.post(
    "/{agent_id}/clone",
    response_model=AgentResponse,
    dependencies=[Depends(limiter.limit("5/hour"))]
)
async def clone_agent(
    agent_id: UUID,
    request: AgentCloneRequest,
    uow: UnitOfWork = Depends(get_uow),
    current_user: User = Depends(get_current_user)
) -> AgentResponse:
    """Clone an existing agent."""
    try:
        # Get original agent
        original = await agent_manager.get_agent(
            uow=uow,
            agent_id=agent_id,
            user_id=current_user.id
        )
        
        # Create clone
        agent = await agent_manager.create_agent(
            uow=uow,
            name=request.name,
            display_name=request.display_name,
            agent_type=original.agent_type,
            graph_definition=original.graph_definition,
            created_by=current_user.id,
            tenant_id=current_user.tenant_id,
            description=request.description or f"Clone of {original.display_name}",
            specialization=original.specialization,
            system_prompt=original.system_prompt,
            capabilities=original.capabilities,
            tool_ids=original.tool_ids,
            is_public=False,
            team_id=request.team_id
        )
        
        return AgentResponse.from_orm(agent)
    
    except AgentNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found"
        )
    except InsufficientPermissionsError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot access this agent"
        )
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get("/{agent_id}/export", response_model=AgentExportResponse)
async def export_agent(
    agent_id: UUID,
    include_memories: bool = Query(False),
    uow: UnitOfWork = Depends(get_uow),
    current_user: User = Depends(get_current_user)
) -> AgentExportResponse:
    """Export an agent configuration."""
    try:
        # Get agent
        agent = await agent_manager.get_agent(
            uow=uow,
            agent_id=agent_id,
            user_id=current_user.id
        )
        
        # Get memories if requested
        memories = []
        if include_memories:
            agent_memories = await agent_manager.get_agent_memories(
                uow=uow,
                agent_id=agent_id,
                limit=1000
            )
            memories = [AgentMemoryResponse.from_orm(m) for m in agent_memories]
        
        return AgentExportResponse(
            agent=AgentDetailResponse.from_orm(agent),
            graph_definition=agent.graph_definition,
            memories=memories,
            exported_at=datetime.utcnow()
        )
    
    except AgentNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found"
        )
    except InsufficientPermissionsError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot export this agent"
        )


@router.post("/default", response_model=List[AgentResponse])
async def create_default_agents(
    uow: UnitOfWork = Depends(get_uow),
    current_user: User = Depends(get_current_user)
) -> List[AgentResponse]:
    """Create default system agents for the tenant."""
    # Check if user is admin
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can create default agents"
        )
    
    try:
        agents = await agent_manager.create_default_agents(
            uow=uow,
            tenant_id=current_user.tenant_id,
            created_by=current_user.id
        )
        return [AgentResponse.from_orm(agent) for agent in agents]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create default agents: {str(e)}"
        )