# Sprint 200: Multi-LLM Foundation with Business Logic

## Sprint Overview

### Goal
Implement the core conversation system with embedded business logic and multi-LLM support, establishing the foundation for the AI platform's intelligence layer.

### Duration
5 weeks (25 working days) - Extended to include essential CRUD APIs

### Prerequisites
- ✅ Authentication system complete (Sprints 100-160)
- ✅ Multi-tenant architecture in place
- ✅ WebSocket infrastructure ready
- ✅ Security hardening complete
- ✅ Database models and repositories exist

### Sprint Objectives
1. Implement essential CRUD APIs (Teams, basic Tenant management)
2. Build conversation management system with business rules
3. Implement message streaming with token tracking
4. Create LLM provider abstraction layer
5. Integrate short-term memory (STM) system
6. Develop basic conversation UI

### 🏗️ Architecture: Client ↔ LangGraph Agents ↔ LLM Providers

This sprint implements the proper architecture where **LangGraph Agents mediate between conversations and LLM providers**:

```
┌─────────┐     ┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│ Client  │────▶│  WebSocket  │────▶│  LangGraph   │────▶│ LLM Providers│
│  (UI)   │◀────│   Events    │◀────│   Agents     │◀────│ (OpenAI, etc)│
└─────────┘     └─────────────┘     └──────────────┘     └─────────────┘
                                            │
                                            ▼
                                    ┌──────────────┐
                                    │Tools, Memory,│
                                    │  MCP, etc.   │
                                    └──────────────┘
```

Key architectural changes:
- **Agent-First**: Every conversation is bound to a LangGraph agent
- **Dynamic Loading**: Agents are loaded from JSON definitions at runtime
- **Provider Abstraction**: Agents use LLM providers, not conversations directly
- **Tool Integration**: Agents can use tools, access memory, call functions
- **Team Agents**: Each team can have its own specialized agent

### 🔄 WebSocket Schema Updates (Based on Platform Vision)

This sprint now includes a **complete production-ready WebSocket event schema** that aligns with the platform's "WebSocket First" architecture. The updated schema includes:

#### New Event Categories:
1. **Connection Management**: Proper handshake, heartbeat, and reconnection handling
2. **Channel Management**: Subscribe/unsubscribe to conversations, teams, and documents
3. **Tool/Function Calling**: Complete event flow for AI tool usage with progress tracking
4. **File Upload & Attachments**: Chunked uploads, direct S3 integration, progress events
5. **Team Collaboration**: Real-time presence, activity feeds, notifications
6. **Document Collaboration**: Operational transforms, cursor tracking, AI suggestions
7. **Agent Interaction**: Full agent execution lifecycle with progress updates
8. **Memory & Preferences**: Real-time memory extraction and preference updates
9. **Model Configuration**: Dynamic temperature, max_tokens, and other settings per conversation
10. **Error & Status Events**: Comprehensive error handling, quota warnings, system announcements

#### Additional API Endpoints:
The sprint also defines missing REST API endpoints for:
- Agent Management
- Memory & Preferences
- Document Management
- Tool & MCP Integration
- Knowledge Graph queries
- Prompt Template Management
- File Storage with presigned URLs
- Analytics & Usage tracking

These additions ensure the platform can deliver on its vision of being a comprehensive Enterprise AI Platform with real-time collaboration capabilities.

---

## Task Breakdown

### Task 200: Essential CRUD APIs
**Priority**: Critical  
**Effort**: 3 days  
**Description**: Implement Teams and basic Tenant management APIs needed for conversations

#### Teams API Implementation

##### Database Schema (Already Exists)
```sql
-- From existing models
CREATE TABLE teams (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE team_members (
    id UUID PRIMARY KEY,
    team_id UUID NOT NULL REFERENCES teams(id),
    user_id UUID NOT NULL REFERENCES users(id),
    role VARCHAR(50) NOT NULL, -- admin, member, viewer
    joined_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(team_id, user_id)
);
```

##### Team Service
```python
# src/services/team_service.py
from typing import List, Optional
from uuid import UUID

class TeamService:
    def __init__(self, db: Database):
        self.db = db
        
    async def create_team(
        self,
        tenant_id: UUID,
        creator_id: UUID,
        name: str,
        description: Optional[str] = None
    ) -> Team:
        """Create a new team"""
        # Business rules
        team_count = await self.db.teams.count(tenant_id=tenant_id)
        tenant_limits = await self._get_tenant_limits(tenant_id)
        
        if team_count >= tenant_limits.max_teams:
            raise TeamLimitExceededError(
                f"Maximum teams reached: {tenant_limits.max_teams}"
            )
            
        # Create team
        team = await self.db.teams.create(
            tenant_id=tenant_id,
            name=name,
            description=description,
            settings={
                "conversation_sharing": True,
                "agent_sharing": True,
                "document_sharing": True
            }
        )
        
        # Add creator as admin
        await self.db.team_members.create(
            team_id=team.id,
            user_id=creator_id,
            role="admin"
        )
        
        # Audit
        await log_audit_event(
            event_type="team_created",
            user_id=creator_id,
            details={"team_id": team.id, "name": name}
        )
        
        return team
        
    async def add_member(
        self,
        team_id: UUID,
        user_id: UUID,
        new_member_id: UUID,
        role: str = "member"
    ) -> TeamMember:
        """Add member to team"""
        # Check permissions
        if not await self._is_team_admin(team_id, user_id):
            raise PermissionDeniedError("Only team admins can add members")
            
        # Check if already member
        existing = await self.db.team_members.find_one(
            team_id=team_id,
            user_id=new_member_id
        )
        if existing:
            raise AlreadyMemberError("User is already a team member")
            
        # Add member
        member = await self.db.team_members.create(
            team_id=team_id,
            user_id=new_member_id,
            role=role
        )
        
        # Notify new member
        await self._notify_new_member(team_id, new_member_id)
        
        return member
        
    async def get_user_teams(
        self,
        user_id: UUID,
        tenant_id: UUID
    ) -> List[TeamWithRole]:
        """Get all teams for a user"""
        teams = await self.db.execute("""
            SELECT t.*, tm.role as user_role
            FROM teams t
            JOIN team_members tm ON t.id = tm.team_id
            WHERE tm.user_id = :user_id
            AND t.tenant_id = :tenant_id
            ORDER BY t.name
        """, {"user_id": user_id, "tenant_id": tenant_id})
        
        return [TeamWithRole.from_orm(t) for t in teams]
```

##### Team API Router
```python
# src/api/v1/teams/router.py
from fastapi import APIRouter, Depends, HTTPException
from typing import List

router = APIRouter(prefix="/api/v1/teams", tags=["teams"])

@router.post("/", response_model=TeamResponse)
async def create_team(
    request: CreateTeamRequest,
    user: User = Depends(get_current_user),
    service: TeamService = Depends(get_team_service)
):
    """Create a new team"""
    try:
        team = await service.create_team(
            tenant_id=user.tenant_id,
            creator_id=user.id,
            name=request.name,
            description=request.description
        )
        return TeamResponse.from_orm(team)
    except TeamLimitExceededError as e:
        raise HTTPException(429, str(e))

@router.get("/", response_model=List[TeamWithRoleResponse])
async def list_teams(
    user: User = Depends(get_current_user),
    service: TeamService = Depends(get_team_service)
):
    """List user's teams"""
    teams = await service.get_user_teams(user.id, user.tenant_id)
    return [TeamWithRoleResponse.from_orm(t) for t in teams]

@router.get("/{team_id}", response_model=TeamDetailResponse)
async def get_team(
    team_id: UUID,
    user: User = Depends(get_current_user),
    service: TeamService = Depends(get_team_service)
):
    """Get team details"""
    team = await service.get_team(team_id, user.id)
    if not team:
        raise HTTPException(404, "Team not found")
    return TeamDetailResponse.from_orm(team)

@router.put("/{team_id}", response_model=TeamResponse)
async def update_team(
    team_id: UUID,
    request: UpdateTeamRequest,
    user: User = Depends(get_current_user),
    service: TeamService = Depends(get_team_service)
):
    """Update team details"""
    if not await service.is_team_admin(team_id, user.id):
        raise HTTPException(403, "Only team admins can update team")
        
    team = await service.update_team(team_id, request.dict(exclude_unset=True))
    return TeamResponse.from_orm(team)

@router.post("/{team_id}/members", response_model=TeamMemberResponse)
async def add_team_member(
    team_id: UUID,
    request: AddTeamMemberRequest,
    user: User = Depends(get_current_user),
    service: TeamService = Depends(get_team_service)
):
    """Add member to team"""
    try:
        member = await service.add_member(
            team_id=team_id,
            user_id=user.id,
            new_member_id=request.user_id,
            role=request.role
        )
        return TeamMemberResponse.from_orm(member)
    except PermissionDeniedError as e:
        raise HTTPException(403, str(e))
    except AlreadyMemberError as e:
        raise HTTPException(409, str(e))

@router.get("/{team_id}/members", response_model=List[TeamMemberResponse])
async def list_team_members(
    team_id: UUID,
    user: User = Depends(get_current_user),
    service: TeamService = Depends(get_team_service)
):
    """List team members"""
    if not await service.is_team_member(team_id, user.id):
        raise HTTPException(403, "Not a team member")
        
    members = await service.get_team_members(team_id)
    return [TeamMemberResponse.from_orm(m) for m in members]

@router.delete("/{team_id}/members/{member_id}")
async def remove_team_member(
    team_id: UUID,
    member_id: UUID,
    user: User = Depends(get_current_user),
    service: TeamService = Depends(get_team_service)
):
    """Remove member from team"""
    if not await service.is_team_admin(team_id, user.id):
        raise HTTPException(403, "Only team admins can remove members")
        
    await service.remove_member(team_id, member_id)
    return {"status": "removed"}
```

##### Request/Response Schemas
```python
# src/api/v1/teams/schemas.py
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class CreateTeamRequest(BaseModel):
    name: str
    description: Optional[str] = None

class UpdateTeamRequest(BaseModel):
    name: Optional[str]
    description: Optional[str]
    settings: Optional[dict]

class AddTeamMemberRequest(BaseModel):
    user_id: UUID
    role: str = "member"  # admin, member, viewer

class TeamResponse(BaseModel):
    id: UUID
    name: str
    description: Optional[str]
    member_count: int
    created_at: datetime
    
class TeamWithRoleResponse(TeamResponse):
    user_role: str  # User's role in this team
    
class TeamMemberResponse(BaseModel):
    id: UUID
    user_id: UUID
    user_name: str
    user_email: str
    role: str
    joined_at: datetime
```

#### Basic Tenant Management API

##### Tenant Settings Service
```python
# src/services/tenant_settings_service.py
class TenantSettingsService:
    def __init__(self, db: Database):
        self.db = db
        
    async def get_tenant_info(
        self,
        tenant_id: UUID,
        user_id: UUID
    ) -> TenantInfo:
        """Get tenant information"""
        # Check user belongs to tenant
        membership = await self.db.tenant_users.find_one(
            tenant_id=tenant_id,
            user_id=user_id
        )
        if not membership:
            raise TenantAccessDeniedError()
            
        tenant = await self.db.tenants.get(tenant_id)
        
        # Get usage stats
        usage = await self._calculate_usage(tenant_id)
        
        return TenantInfo(
            id=tenant.id,
            name=tenant.name,
            settings=tenant.settings,
            limits=tenant.limits,
            usage=usage,
            user_role=membership.role
        )
        
    async def update_tenant_settings(
        self,
        tenant_id: UUID,
        user_id: UUID,
        settings: dict
    ) -> Tenant:
        """Update tenant settings (admin only)"""
        # Check admin permission
        if not await self._is_tenant_admin(tenant_id, user_id):
            raise PermissionDeniedError("Only tenant admins can update settings")
            
        # Validate settings
        validated_settings = self._validate_settings(settings)
        
        # Update
        tenant = await self.db.tenants.update(
            tenant_id,
            settings=validated_settings,
            updated_at=datetime.utcnow()
        )
        
        return tenant
```

##### Tenant API Router
```python
# src/api/v1/tenants/router.py
router = APIRouter(prefix="/api/v1/tenants", tags=["tenants"])

@router.get("/current", response_model=TenantInfoResponse)
async def get_current_tenant(
    user: User = Depends(get_current_user),
    service: TenantSettingsService = Depends(get_tenant_service)
):
    """Get current tenant information"""
    tenant_info = await service.get_tenant_info(user.tenant_id, user.id)
    return TenantInfoResponse.from_orm(tenant_info)

@router.get("/current/usage", response_model=TenantUsageResponse)
async def get_tenant_usage(
    user: User = Depends(get_current_user),
    service: TenantSettingsService = Depends(get_tenant_service)
):
    """Get tenant usage statistics"""
    usage = await service.get_usage_stats(user.tenant_id, user.id)
    return TenantUsageResponse.from_orm(usage)

@router.put("/current/settings", response_model=TenantSettingsResponse)
async def update_tenant_settings(
    request: UpdateTenantSettingsRequest,
    user: User = Depends(get_current_user),
    service: TenantSettingsService = Depends(get_tenant_service)
):
    """Update tenant settings (admin only)"""
    try:
        tenant = await service.update_tenant_settings(
            user.tenant_id,
            user.id,
            request.settings
        )
        return TenantSettingsResponse(settings=tenant.settings)
    except PermissionDeniedError as e:
        raise HTTPException(403, str(e))
```

### Task 201: Conversation System with Business Logic
**Priority**: Critical  
**Effort**: 4 days  
**Description**: Implement core conversation CRUD with embedded business rules and team support

#### Database Schema
```sql
-- Conversations table with business fields, team support, and agent binding
CREATE TABLE conversations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    user_id UUID NOT NULL REFERENCES users(id),
    team_id UUID REFERENCES teams(id), -- NULL for personal conversations
    agent_id UUID NOT NULL REFERENCES agents(id), -- NEW: Agent binding
    title VARCHAR(255) DEFAULT 'New Conversation',
    model VARCHAR(50) NOT NULL DEFAULT 'gpt-4',
    status VARCHAR(20) DEFAULT 'active', -- active, archived, deleted
    visibility VARCHAR(20) DEFAULT 'private', -- private, team, public
    
    -- Business metrics
    total_tokens INTEGER DEFAULT 0,
    total_cost DECIMAL(10,4) DEFAULT 0,
    message_count INTEGER DEFAULT 0,
    last_checkpoint_at TIMESTAMP,
    last_activity_at TIMESTAMP DEFAULT NOW(),
    
    -- Limits (from tenant plan)
    max_tokens_per_message INTEGER DEFAULT 4096,
    max_total_tokens INTEGER DEFAULT 100000,
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    -- Indexes
    INDEX idx_conversations_tenant_user (tenant_id, user_id),
    INDEX idx_conversations_team (team_id) WHERE team_id IS NOT NULL,
    INDEX idx_conversations_status (status),
    INDEX idx_conversations_last_activity (last_activity_at DESC)
);

-- Conversation sharing
CREATE TABLE conversation_shares (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    shared_with_user_id UUID REFERENCES users(id),
    shared_with_team_id UUID REFERENCES teams(id),
    permission VARCHAR(20) NOT NULL DEFAULT 'read', -- read, write
    shared_by UUID NOT NULL REFERENCES users(id),
    shared_at TIMESTAMP DEFAULT NOW(),
    
    CHECK (
        (shared_with_user_id IS NOT NULL AND shared_with_team_id IS NULL) OR
        (shared_with_user_id IS NULL AND shared_with_team_id IS NOT NULL)
    )
);

-- Conversation checkpoints for summarization
CREATE TABLE conversation_checkpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    message_count INTEGER NOT NULL,
    summary TEXT NOT NULL,
    key_points JSONB DEFAULT '[]',
    entities JSONB DEFAULT '[]',
    created_at TIMESTAMP DEFAULT NOW(),
    
    INDEX idx_checkpoints_conversation (conversation_id)
);
```

#### Service Implementation with LangGraph Integration
```python
# src/services/conversation_service.py
from typing import Optional, List, AsyncIterator
from uuid import UUID
from datetime import datetime, timedelta

class ConversationService:
    def __init__(
        self, 
        db: Database, 
        cache: Redis,
        agent_manager: AgentManager  # NEW: LangGraph integration
    ):
        self.db = db
        self.cache = cache
        self.agent_manager = agent_manager
        self.checkpoint_threshold = 50  # messages
        
    async def create_conversation(
        self, 
        user_id: UUID, 
        tenant_id: UUID,
        agent_id: Optional[UUID] = None,  # NEW: Agent selection
        model: str = "gpt-4",  # Fallback for agent's LLM choice
        title: Optional[str] = None,
        team_id: Optional[UUID] = None,
        visibility: str = "private"
    ) -> Conversation:
        """Create new conversation with business rules"""
        # 1. Determine agent to use
        if not agent_id:
            if team_id:
                # Get team's default agent
                agent_id = await self._get_team_agent(team_id)
            else:
                # Get user's default agent or system default
                agent_id = await self._get_default_agent(user_id, tenant_id)
                
        # 2. Validate agent access
        agent = await self.agent_manager.get_agent(agent_id, tenant_id)
        if not agent:
            raise AgentNotFoundError(f"Agent {agent_id} not found")
            
        # 3. Override model with agent's configured model
        model = agent.config.get('default_model', model)
        
        # 4. Validate user has access to model through agent
        if not await self._validate_model_access(user_id, tenant_id, model):
            raise ModelAccessDeniedError(f"No access to model: {model}")
            
        # 5. Validate team membership if team conversation
        if team_id:
            if not await self._is_team_member(team_id, user_id):
                raise TeamAccessDeniedError("Not a member of this team")
            visibility = "team"  # Force team visibility
            
        # 6. Check conversation limits
        active_count = await self._get_active_conversation_count(user_id, team_id)
        tenant_limits = await self._get_tenant_limits(tenant_id)
        
        limit_key = "max_team_conversations" if team_id else "max_conversations"
        max_allowed = getattr(tenant_limits, limit_key, 100)
        
        if active_count >= max_allowed:
            raise ConversationLimitExceededError(
                f"Maximum conversations reached: {max_allowed}"
            )
            
        # 7. Create conversation with agent binding
        conversation = await self.db.conversations.create(
            user_id=user_id,
            tenant_id=tenant_id,
            team_id=team_id,
            agent_id=agent_id,  # NEW: Bind agent to conversation
            model=model,
            title=title or "New Conversation",
            visibility=visibility,
            max_tokens_per_message=tenant_limits.max_tokens_per_message,
            max_total_tokens=tenant_limits.max_total_tokens,
            metadata={
                "agent_name": agent.name,
                "agent_type": agent.type,
                "agent_version": agent.version
            }
        )
        
        # 5. Initialize STM entry
        await self._init_stm(conversation.id)
        
        # 6. Notify team if team conversation
        if team_id:
            await self._notify_team_new_conversation(team_id, conversation)
        
        # 7. Audit log
        await log_audit_event(
            event_type="conversation_created",
            user_id=user_id,
            details={
                "conversation_id": conversation.id, 
                "model": model,
                "team_id": team_id,
                "visibility": visibility
            }
        )
        
        return conversation
        
    async def get_conversation(
        self,
        conversation_id: UUID,
        user_id: UUID
    ) -> Optional[Conversation]:
        """Get conversation with access check"""
        conversation = await self.db.conversations.get(conversation_id)
        if not conversation:
            return None
            
        # Check access
        if not await self._can_access_conversation(conversation, user_id):
            raise ConversationAccessDeniedError()
            
        return conversation
        
    async def _can_access_conversation(
        self,
        conversation: Conversation,
        user_id: UUID
    ) -> bool:
        """Check if user can access conversation"""
        # Owner always has access
        if conversation.user_id == user_id:
            return True
            
        # Team members can access team conversations
        if conversation.team_id:
            return await self._is_team_member(conversation.team_id, user_id)
            
        # Check explicit shares
        share = await self.db.conversation_shares.find_one(
            conversation_id=conversation.id,
            shared_with_user_id=user_id
        )
        
        return share is not None
        
    async def update_conversation_title(
        self,
        conversation_id: UUID,
        user_id: UUID
    ) -> str:
        """Auto-generate title from first messages"""
        conversation = await self._get_user_conversation(conversation_id, user_id)
        
        # Only update if still default title
        if conversation.title != "New Conversation":
            return conversation.title
            
        # Get first few messages
        messages = await self.db.messages.find(
            conversation_id=conversation_id,
            limit=3
        )
        
        if len(messages) < 2:  # Need at least user + assistant message
            return conversation.title
            
        # Generate title using LLM
        prompt = self._build_title_prompt(messages)
        title = await self._generate_title(prompt)
        
        # Update conversation
        await self.db.conversations.update(
            conversation_id,
            title=title[:255]  # Enforce length limit
        )
        
        return title
        
    async def archive_conversation(
        self,
        conversation_id: UUID,
        user_id: UUID
    ) -> None:
        """Archive conversation with cleanup"""
        conversation = await self._get_user_conversation(conversation_id, user_id)
        
        # Update status
        await self.db.conversations.update(
            conversation_id,
            status="archived",
            updated_at=datetime.utcnow()
        )
        
        # Clear from STM
        await self._clear_stm(conversation_id)
        
        # Audit log
        await log_audit_event(
            event_type="conversation_archived",
            user_id=user_id,
            details={"conversation_id": conversation_id}
        )
        
    async def enforce_token_limits(
        self,
        conversation_id: UUID,
        new_tokens: int
    ) -> None:
        """Check and enforce token limits"""
        conversation = await self.db.conversations.get(conversation_id)
        
        # Check per-message limit
        if new_tokens > conversation.max_tokens_per_message:
            raise TokenLimitExceededError(
                f"Message exceeds token limit: {new_tokens} > {conversation.max_tokens_per_message}"
            )
            
        # Check total limit
        if conversation.total_tokens + new_tokens > conversation.max_total_tokens:
            raise ConversationTokenLimitExceededError(
                f"Conversation would exceed total token limit"
            )
            
    async def check_checkpoint_needed(
        self,
        conversation_id: UUID
    ) -> bool:
        """Check if conversation needs checkpoint"""
        conversation = await self.db.conversations.get(conversation_id)
        
        # No checkpoint yet
        if not conversation.last_checkpoint_at:
            return conversation.message_count >= self.checkpoint_threshold
            
        # Messages since last checkpoint
        messages_since = await self.db.messages.count(
            conversation_id=conversation_id,
            created_after=conversation.last_checkpoint_at
        )
        
        return messages_since >= self.checkpoint_threshold
```

#### API Endpoints
```python
# src/api/v1/conversations/router.py
from fastapi import APIRouter, Depends, HTTPException
from typing import List

router = APIRouter(prefix="/api/v1/conversations", tags=["conversations"])

@router.post("/", response_model=ConversationResponse)
async def create_conversation(
    request: CreateConversationRequest,
    user: User = Depends(get_current_user),
    service: ConversationService = Depends(get_conversation_service)
):
    """Create new conversation"""
    try:
        conversation = await service.create_conversation(
            user_id=user.id,
            tenant_id=user.tenant_id,
            model=request.model,
            title=request.title
        )
        return ConversationResponse.from_orm(conversation)
    except ModelAccessDeniedError as e:
        raise HTTPException(403, str(e))
    except ConversationLimitExceededError as e:
        raise HTTPException(429, str(e))

@router.get("/", response_model=List[ConversationSummary])
async def list_conversations(
    status: Optional[str] = "active",
    limit: int = Query(20, le=100),
    offset: int = 0,
    user: User = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """List user conversations"""
    conversations = await db.conversations.find_many(
        user_id=user.id,
        tenant_id=user.tenant_id,
        status=status,
        order_by="last_activity_at DESC",
        limit=limit,
        offset=offset
    )
    return [ConversationSummary.from_orm(c) for c in conversations]

@router.patch("/{conversation_id}/archive")
async def archive_conversation(
    conversation_id: UUID,
    user: User = Depends(get_current_user),
    service: ConversationService = Depends(get_conversation_service)
):
    """Archive conversation"""
    await service.archive_conversation(conversation_id, user.id)
    return {"status": "archived"}
```

### Task 202: Message Management and Streaming
**Priority**: Critical  
**Effort**: 4 days  
**Description**: Implement message handling with WebSocket streaming and token tracking

#### Database Schema
```sql
-- Messages with token tracking
CREATE TABLE messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    role VARCHAR(20) NOT NULL, -- user, assistant, system
    content TEXT NOT NULL,
    
    -- Token tracking
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    total_tokens INTEGER,
    cost DECIMAL(10,6),
    
    -- Metadata
    model_used VARCHAR(50),
    processing_time_ms INTEGER,
    error TEXT,
    
    created_at TIMESTAMP DEFAULT NOW(),
    
    -- Indexes
    INDEX idx_messages_conversation (conversation_id),
    INDEX idx_messages_created (created_at)
);

-- Message attachments (future)
CREATE TABLE message_attachments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL, -- image, document, code
    url TEXT NOT NULL,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW()
);
```

#### Message Service with Agent Execution
```python
# src/services/message_service.py
class MessageService:
    def __init__(
        self, 
        db: Database,
        conversation_service: ConversationService,
        agent_executor: AgentExecutor,  # NEW: Instead of direct LLM
        token_counter: TokenCounter
    ):
        self.db = db
        self.conversation_service = conversation_service
        self.agent_executor = agent_executor
        self.token_counter = token_counter
        
    async def add_user_message(
        self,
        conversation_id: UUID,
        user_id: UUID,
        content: str
    ) -> Message:
        """Add user message with validation"""
        # 1. Validate conversation access
        conversation = await self.conversation_service.get_user_conversation(
            conversation_id, user_id
        )
        
        if conversation.status != "active":
            raise ConversationNotActiveError()
            
        # 2. Count tokens
        token_count = await self.token_counter.count(content, conversation.model)
        
        # 3. Enforce limits
        await self.conversation_service.enforce_token_limits(
            conversation_id, token_count
        )
        
        # 4. Create message
        message = await self.db.messages.create(
            conversation_id=conversation_id,
            role="user",
            content=content,
            total_tokens=token_count
        )
        
        # 5. Update conversation metrics
        await self._update_conversation_metrics(
            conversation_id,
            tokens=token_count,
            message_count=1
        )
        
        return message
        
    async def stream_assistant_response(
        self,
        conversation_id: UUID,
        user_id: UUID,
        user_message_id: UUID
    ) -> AsyncIterator[StreamEvent]:
        """Stream AI response through agent with token tracking"""
        # 1. Get conversation context
        conversation = await self.conversation_service.get_user_conversation(
            conversation_id, user_id
        )
        
        # 2. Build conversation history
        history = await self._build_conversation_history(conversation_id)
        
        # 3. Get user preferences and context
        preferences = await self._get_user_preferences(user_id)
        stm_context = await self._get_stm_context(conversation_id)
        
        # 4. Prepare agent input
        agent_input = {
            "conversation_id": conversation_id,
            "user_id": user_id,
            "message": history[-1]["content"],  # Latest user message
            "history": history[:-1],  # Previous messages
            "preferences": preferences,
            "stm_context": stm_context,
            "team_id": conversation.team_id
        }
        
        # 5. Start streaming through agent
        start_time = datetime.utcnow()
        response_chunks = []
        prompt_tokens = 0
        completion_tokens = 0
        
        try:
            # Stream from Agent (which internally uses LLM)
            async for event in self.agent_executor.stream_execution(
                agent_id=conversation.agent_id,
                input_data=agent_input,
                tenant_id=conversation.tenant_id
            ):
                # Handle different agent event types
                if event.type == "llm_start":
                    yield StreamEvent(
                        type="assistant.start",
                        model=event.data.get("model"),
                        agent_node=event.data.get("node_id")
                    )
                    
                elif event.type == "llm_token":
                    response_chunks.append(event.content)
                    completion_tokens += 1
                    
                    yield StreamEvent(
                        type="assistant.content",
                        content=event.content,
                        tokens_used=completion_tokens
                    )
                    
                elif event.type == "llm_complete":
                    prompt_tokens = event.data.get("prompt_tokens", 0)
                    
                elif event.type == "tool_start":
                    yield StreamEvent(
                        type="tool.call.start",
                        tool_name=event.data.get("tool_name"),
                        arguments=event.data.get("arguments")
                    )
                    
                elif event.type == "tool_complete":
                    yield StreamEvent(
                        type="tool.call.complete",
                        tool_name=event.data.get("tool_name"),
                        result=event.data.get("result")
                    )
                    
                elif event.type == "agent_thinking":
                    yield StreamEvent(
                        type="assistant.thinking",
                        status=event.data.get("status"),
                        current_node=event.data.get("node_id")
                    )
                    
            # Complete response
            full_response = "".join(response_chunks)
            total_tokens = prompt_tokens + completion_tokens
            
            # Calculate cost
            cost = await self._calculate_cost(
                conversation.model,
                prompt_tokens,
                completion_tokens
            )
            
            # Save assistant message
            assistant_message = await self.db.messages.create(
                conversation_id=conversation_id,
                role="assistant",
                content=full_response,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                cost=cost,
                model_used=conversation.model,
                processing_time_ms=int(
                    (datetime.utcnow() - start_time).total_seconds() * 1000
                )
            )
            
            # Update conversation
            await self._update_conversation_metrics(
                conversation_id,
                tokens=total_tokens,
                cost=cost,
                message_count=1
            )
            
            # Auto-generate title if needed
            if conversation.message_count <= 2:
                new_title = await self.conversation_service.update_conversation_title(
                    conversation_id, user_id
                )
                yield StreamEvent(
                    type="title_updated",
                    content=new_title
                )
                
            # Check if checkpoint needed
            if await self.conversation_service.check_checkpoint_needed(conversation_id):
                asyncio.create_task(
                    self._create_checkpoint(conversation_id)
                )
                
            # Final event
            yield StreamEvent(
                type="complete",
                message_id=assistant_message.id,
                total_tokens=total_tokens,
                cost=float(cost)
            )
            
        except Exception as e:
            # Log error
            logger.error(f"Stream error: {e}", conversation_id=conversation_id)
            
            # Save error message
            await self.db.messages.create(
                conversation_id=conversation_id,
                role="assistant",
                content="An error occurred while generating the response.",
                error=str(e)
            )
            
            yield StreamEvent(
                type="error",
                error=str(e)
            )
            
    async def _build_context(self, conversation_id: UUID) -> List[dict]:
        """Build conversation context with STM"""
        # Get recent messages
        messages = await self.db.messages.find(
            conversation_id=conversation_id,
            order_by="created_at ASC",
            limit=50  # Adjust based on model context window
        )
        
        # Get STM data
        stm_context = await self._get_stm_context(conversation_id)
        
        # Build message list
        context = []
        
        # Add STM as system message if exists
        if stm_context:
            context.append({
                "role": "system",
                "content": f"Context from previous conversation: {stm_context}"
            })
            
        # Add conversation messages
        for msg in messages:
            context.append({
                "role": msg.role,
                "content": msg.content
            })
            
        return context
```

#### WebSocket Handler
```python
# src/api/v1/websocket/chat.py
from fastapi import WebSocket, WebSocketDisconnect
from typing import Dict, Any

class ChatWebSocketHandler:
    def __init__(self):
        self.message_service = MessageService()
        self.active_connections: Dict[str, WebSocket] = {}
        
    async def connect(self, websocket: WebSocket, user_id: str):
        """Handle WebSocket connection"""
        await websocket.accept()
        self.active_connections[user_id] = websocket
        
        # Send connection confirmation
        await websocket.send_json({
            "type": "connection",
            "status": "connected",
            "user_id": user_id
        })
        
    async def disconnect(self, user_id: str):
        """Handle disconnection"""
        if user_id in self.active_connections:
            del self.active_connections[user_id]
            
    async def handle_message(
        self, 
        websocket: WebSocket,
        user_id: str,
        message: dict
    ):
        """Route incoming WebSocket messages"""
        msg_type = message.get("type")
        
        if msg_type == "chat.message":
            await self._handle_chat_message(websocket, user_id, message)
        elif msg_type == "chat.typing":
            await self._handle_typing_indicator(user_id, message)
        else:
            await websocket.send_json({
                "type": "error",
                "error": f"Unknown message type: {msg_type}"
            })
            
    async def _handle_chat_message(
        self,
        websocket: WebSocket,
        user_id: str,
        message: dict
    ):
        """Handle chat message and stream response"""
        conversation_id = message.get("conversation_id")
        content = message.get("content")
        
        try:
            # Add user message
            user_msg = await self.message_service.add_user_message(
                conversation_id=UUID(conversation_id),
                user_id=UUID(user_id),
                content=content
            )
            
            # Acknowledge receipt
            await websocket.send_json({
                "type": "message.received",
                "message_id": str(user_msg.id),
                "timestamp": user_msg.created_at.isoformat()
            })
            
            # Stream assistant response
            async for event in self.message_service.stream_assistant_response(
                conversation_id=UUID(conversation_id),
                user_id=UUID(user_id),
                user_message_id=user_msg.id
            ):
                await websocket.send_json({
                    "type": f"assistant.{event.type}",
                    **event.dict()
                })
                
        except ConversationNotActiveError:
            await websocket.send_json({
                "type": "error",
                "error": "Conversation is not active"
            })
        except TokenLimitExceededError as e:
            await websocket.send_json({
                "type": "error",
                "error": str(e),
                "error_type": "token_limit"
            })
        except Exception as e:
            logger.error(f"Chat message error: {e}")
            await websocket.send_json({
                "type": "error",
                "error": "An error occurred processing your message"
            })

# WebSocket route
@router.websocket("/ws/chat")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(...),
    handler: ChatWebSocketHandler = Depends()
):
    """WebSocket endpoint for chat"""
    # Validate token
    try:
        user = await validate_websocket_token(token)
    except InvalidTokenError:
        await websocket.close(code=4001, reason="Invalid token")
        return
        
    # Connect
    await handler.connect(websocket, str(user.id))
    
    try:
        while True:
            # Receive message
            data = await websocket.receive_json()
            
            # Handle message
            await handler.handle_message(websocket, str(user.id), data)
            
    except WebSocketDisconnect:
        await handler.disconnect(str(user.id))
```

### Task 203: Agent System with LLM Provider Integration
**Priority**: High  
**Effort**: 5 days  
**Description**: Create LangGraph agent system that uses LLM providers

#### Agent Executor (Bridges Conversations to LangGraph)
```python
# src/agents/executor.py
from typing import AsyncIterator, Dict, Any
from langgraph.graph import Graph
from uuid import UUID

class AgentExecutor:
    """
    Executes LangGraph agents, bridging between conversations and LLM providers
    """
    
    def __init__(
        self,
        agent_loader: DynamicAgentLoader,
        llm_router: LLMProviderManager,
        tool_registry: ToolRegistry,
        memory_manager: MemoryManager
    ):
        self.agent_loader = agent_loader
        self.llm_router = llm_router
        self.tool_registry = tool_registry
        self.memory_manager = memory_manager
        self.agent_cache = {}
        
    async def stream_execution(
        self,
        agent_id: UUID,
        input_data: Dict[str, Any],
        tenant_id: UUID
    ) -> AsyncIterator[AgentEvent]:
        """
        Stream agent execution events
        """
        # 1. Load agent (from cache or DB)
        agent = await self._get_or_load_agent(agent_id, tenant_id)
        
        # 2. Create execution context
        context = ExecutionContext(
            tenant_id=tenant_id,
            agent_id=agent_id,
            llm_router=self.llm_router,
            tool_registry=self.tool_registry,
            memory_manager=self.memory_manager
        )
        
        # 3. Execute agent graph with streaming
        async for event in agent.astream_events(
            input_data,
            config={"context": context}
        ):
            # Transform LangGraph events to our format
            if event["event"] == "on_llm_start":
                yield AgentEvent(
                    type="llm_start",
                    data={
                        "model": event["data"]["model"],
                        "node_id": event["metadata"]["langgraph_node"]
                    }
                )
                
            elif event["event"] == "on_llm_new_token":
                yield AgentEvent(
                    type="llm_token",
                    content=event["data"]["chunk"]
                )
                
            elif event["event"] == "on_llm_end":
                yield AgentEvent(
                    type="llm_complete",
                    data={
                        "prompt_tokens": event["data"]["llm_output"]["token_usage"]["prompt_tokens"],
                        "completion_tokens": event["data"]["llm_output"]["token_usage"]["completion_tokens"]
                    }
                )
                
            elif event["event"] == "on_tool_start":
                yield AgentEvent(
                    type="tool_start",
                    data={
                        "tool_name": event["name"],
                        "arguments": event["data"]["input"]
                    }
                )
                
            elif event["event"] == "on_tool_end":
                yield AgentEvent(
                    type="tool_complete",
                    data={
                        "tool_name": event["name"],
                        "result": event["data"]["output"]
                    }
                )
                
    async def _get_or_load_agent(self, agent_id: UUID, tenant_id: UUID) -> Graph:
        """Load agent from cache or database"""
        cache_key = f"{tenant_id}:{agent_id}"
        
        if cache_key not in self.agent_cache:
            # Load agent definition from DB
            agent_def = await self.db.agents.get(agent_id, tenant_id)
            if not agent_def:
                raise AgentNotFoundError(f"Agent {agent_id} not found")
                
            # Use dynamic loader to create LangGraph instance
            graph = await self.agent_loader.load_agent(agent_def.definition)
            self.agent_cache[cache_key] = graph
            
        return self.agent_cache[cache_key]
```

#### Agent Manager
```python
# src/agents/manager.py
class AgentManager:
    """
    Manages agents lifecycle and access
    """
    
    def __init__(self, db: Database):
        self.db = db
        
    async def get_agent(self, agent_id: UUID, tenant_id: UUID) -> Agent:
        """Get agent with access control"""
        agent = await self.db.agents.find_one(
            id=agent_id,
            tenant_id=tenant_id
        )
        
        if not agent:
            # Check if it's a shared/system agent
            agent = await self.db.agents.find_one(
                id=agent_id,
                is_system=True
            )
            
        return agent
        
    async def get_default_agent(self, user_id: UUID, tenant_id: UUID) -> UUID:
        """Get user's default agent or system default"""
        # Check user preference
        pref = await self.db.user_preferences.find_one(
            user_id=user_id,
            key="default_agent_id"
        )
        
        if pref:
            return UUID(pref.value)
            
        # Get tenant default
        tenant = await self.db.tenants.get(tenant_id)
        if tenant.default_agent_id:
            return tenant.default_agent_id
            
        # Return system default
        return UUID("00000000-0000-0000-0000-000000000001")  # General Assistant
        
    async def get_team_agent(self, team_id: UUID) -> UUID:
        """Get team's assigned agent"""
        team = await self.db.teams.get(team_id)
        
        if not team.agent_id:
            # Create default team agent if none exists
            agent = await self.create_team_agent(team_id, team.name)
            return agent.id
            
        return team.agent_id
```

#### LLM Provider Interface (Used by Agents)
```python
# src/llm/base.py
from abc import ABC, abstractmethod
from typing import AsyncIterator, Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class ModelConfig:
    temperature: float = 0.7
    max_tokens: Optional[int] = None
    top_p: float = 1.0
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0
    stop_sequences: Optional[List[str]] = None

@dataclass
class CompletionChunk:
    content: Optional[str] = None
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    finish_reason: Optional[str] = None

class LLMProvider(ABC):
    """Base class for LLM providers"""
    
    @abstractmethod
    async def complete(
        self,
        messages: List[Dict[str, str]],
        model: str,
        config: ModelConfig
    ) -> str:
        """Get completion from LLM"""
        pass
        
    @abstractmethod
    async def stream_completion(
        self,
        messages: List[Dict[str, str]],
        model: str,
        config: ModelConfig
    ) -> AsyncIterator[CompletionChunk]:
        """Stream completion from LLM"""
        pass
        
    @abstractmethod
    async def count_tokens(self, text: str, model: str) -> int:
        """Count tokens for text"""
        pass
        
    @abstractmethod
    async def check_health(self) -> Dict[str, Any]:
        """Check provider health"""
        pass
        
    @abstractmethod
    def get_supported_models(self) -> List[str]:
        """Get list of supported models"""
        pass
        
    @abstractmethod
    def estimate_cost(
        self, 
        model: str,
        prompt_tokens: int,
        completion_tokens: int
    ) -> float:
        """Estimate cost for tokens"""
        pass
```

#### OpenAI Implementation
```python
# src/llm/providers/openai_provider.py
import openai
from typing import AsyncIterator, Dict, Any, List
import tiktoken

class OpenAIProvider(LLMProvider):
    """OpenAI provider implementation"""
    
    def __init__(self, api_key: str, organization: Optional[str] = None):
        self.client = openai.AsyncOpenAI(
            api_key=api_key,
            organization=organization
        )
        self.supported_models = [
            "gpt-4-turbo-preview",
            "gpt-4",
            "gpt-3.5-turbo",
            "gpt-3.5-turbo-16k"
        ]
        self.model_costs = {
            "gpt-4-turbo-preview": {"prompt": 0.01, "completion": 0.03},
            "gpt-4": {"prompt": 0.03, "completion": 0.06},
            "gpt-3.5-turbo": {"prompt": 0.0005, "completion": 0.0015},
            "gpt-3.5-turbo-16k": {"prompt": 0.003, "completion": 0.004}
        }
        
    async def complete(
        self,
        messages: List[Dict[str, str]],
        model: str,
        config: ModelConfig
    ) -> str:
        """Get completion from OpenAI"""
        response = await self.client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            top_p=config.top_p,
            frequency_penalty=config.frequency_penalty,
            presence_penalty=config.presence_penalty,
            stop=config.stop_sequences
        )
        return response.choices[0].message.content
        
    async def stream_completion(
        self,
        messages: List[Dict[str, str]],
        model: str,
        config: ModelConfig
    ) -> AsyncIterator[CompletionChunk]:
        """Stream completion from OpenAI"""
        stream = await self.client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            top_p=config.top_p,
            frequency_penalty=config.frequency_penalty,
            presence_penalty=config.presence_penalty,
            stop=config.stop_sequences,
            stream=True,
            stream_options={"include_usage": True}
        )
        
        async for chunk in stream:
            if chunk.usage:
                yield CompletionChunk(
                    prompt_tokens=chunk.usage.prompt_tokens,
                    completion_tokens=chunk.usage.completion_tokens
                )
            elif chunk.choices[0].delta.content:
                yield CompletionChunk(
                    content=chunk.choices[0].delta.content
                )
            if chunk.choices[0].finish_reason:
                yield CompletionChunk(
                    finish_reason=chunk.choices[0].finish_reason
                )
                
    async def count_tokens(self, text: str, model: str) -> int:
        """Count tokens using tiktoken"""
        try:
            encoding = tiktoken.encoding_for_model(model)
        except KeyError:
            encoding = tiktoken.get_encoding("cl100k_base")
            
        return len(encoding.encode(text))
        
    async def check_health(self) -> Dict[str, Any]:
        """Check OpenAI API health"""
        try:
            # Make a minimal API call
            response = await self.client.models.list()
            return {
                "status": "healthy",
                "provider": "openai",
                "available_models": len(response.data)
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "provider": "openai",
                "error": str(e)
            }
            
    def get_supported_models(self) -> List[str]:
        """Get supported models"""
        return self.supported_models
        
    def estimate_cost(
        self,
        model: str,
        prompt_tokens: int,
        completion_tokens: int
    ) -> float:
        """Calculate cost in USD"""
        if model not in self.model_costs:
            return 0.0
            
        costs = self.model_costs[model]
        prompt_cost = (prompt_tokens / 1000) * costs["prompt"]
        completion_cost = (completion_tokens / 1000) * costs["completion"]
        
        return prompt_cost + completion_cost
```

#### Dynamic Agent Loader (From LangGraph Integration Doc)
```python
# src/agents/loader.py
from typing import Dict, Any, Optional
from langgraph.graph import Graph, Node
from langgraph.graph.state import GraphState
import json

class DynamicAgentLoader:
    """
    Loads agent definitions from JSON and creates LangGraph instances
    """
    
    def __init__(self, 
                 tool_registry: ToolRegistry,
                 memory_manager: MemoryManager,
                 llm_router: LLMProviderManager):
        self.tool_registry = tool_registry
        self.memory_manager = memory_manager
        self.llm_router = llm_router
        self.node_factories = self._initialize_node_factories()
    
    async def load_agent(self, agent_definition: Dict[str, Any]) -> Graph:
        """
        Main method to load an agent from JSON
        """
        # Validate schema
        self._validate_schema(agent_definition)
        
        # Create graph
        graph = Graph()
        
        # Create state schema
        state_schema = self._create_state_schema(agent_definition)
        graph.set_state_schema(state_schema)
        
        # Add nodes
        for node_def in agent_definition['graph']['nodes']:
            node = self._create_node(node_def, agent_definition['config'])
            graph.add_node(node_def['id'], node)
        
        # Add edges
        for edge_def in agent_definition['graph']['edges']:
            if 'condition' in edge_def:
                condition = self._create_condition(edge_def['condition'])
                graph.add_conditional_edge(
                    edge_def['from'],
                    condition,
                    {edge_def['to']: edge_def['to']}
                )
            else:
                graph.add_edge(edge_def['from'], edge_def['to'])
        
        # Set entry point
        graph.set_entry_point(agent_definition['graph']['entry_point'])
        
        return graph.compile()
    
    def _create_llm_node(self, node_config: Dict, agent_config: Dict) -> Node:
        """
        Creates an LLM Node that uses our LLM providers
        """
        async def llm_node(state: GraphState) -> GraphState:
            # Get execution context from config
            context = state.get("__context__")
            
            # Get LLM provider from context
            llm_router = context.llm_router
            tenant_id = context.tenant_id
            
            # Build prompt
            prompt_template = node_config['prompt_template']
            prompt = self._render_template(prompt_template, state)
            
            # Get model configuration
            model = node_config.get('model', agent_config.get('default_model'))
            provider = llm_router.get_provider(tenant_id, model)
            
            # Stream response
            response_chunks = []
            async for chunk in provider.stream_completion(
                messages=[{"role": "user", "content": prompt}],
                model=model,
                config=ModelConfig(
                    temperature=node_config.get('temperature', agent_config.get('temperature', 0.7)),
                    max_tokens=node_config.get('max_tokens', agent_config.get('max_tokens', 2000))
                )
            ):
                if chunk.content:
                    response_chunks.append(chunk.content)
                    # Emit streaming event
                    await state.emit_event("llm_token", {"chunk": chunk.content})
            
            # Parse output if needed
            full_response = "".join(response_chunks)
            
            if node_config.get('output_parser') == 'json':
                try:
                    result = json.loads(full_response)
                    state.update(result)
                except json.JSONDecodeError:
                    state['error'] = 'Failed to parse JSON response'
            else:
                state['result'] = full_response
            
            return state
        
        return llm_node
```

#### Provider Manager
```python
# src/llm/manager.py
from typing import Dict, Optional
import json
from cryptography.fernet import Fernet

class LLMProviderManager:
    """Manages multiple LLM providers with secure key storage"""
    
    def __init__(self, encryption_key: bytes):
        self.providers: Dict[str, LLMProvider] = {}
        self.fernet = Fernet(encryption_key)
        self.provider_classes = {
            "openai": OpenAIProvider,
            "anthropic": AnthropicProvider,  # TODO
            "google": GoogleProvider,  # TODO
            "azure": AzureOpenAIProvider,  # TODO
            "ollama": OllamaProvider  # TODO
        }
        
    async def add_provider(
        self,
        tenant_id: UUID,
        provider_type: str,
        api_key: str,
        config: Dict[str, Any]
    ) -> str:
        """Add provider for tenant with encrypted key storage"""
        # Encrypt API key
        encrypted_key = self.fernet.encrypt(api_key.encode()).decode()
        
        # Store in database
        provider_record = await self.db.llm_providers.create(
            tenant_id=tenant_id,
            provider_type=provider_type,
            encrypted_api_key=encrypted_key,
            config=config,
            is_active=True
        )
        
        # Initialize provider
        provider_class = self.provider_classes.get(provider_type)
        if not provider_class:
            raise ValueError(f"Unknown provider type: {provider_type}")
            
        provider = provider_class(api_key=api_key, **config)
        
        # Test provider
        health = await provider.check_health()
        if health["status"] != "healthy":
            raise ProviderHealthCheckError(f"Provider unhealthy: {health}")
            
        # Cache provider instance
        cache_key = f"{tenant_id}:{provider_type}"
        self.providers[cache_key] = provider
        
        return provider_record.id
        
    async def get_provider(
        self,
        tenant_id: UUID,
        model: str
    ) -> LLMProvider:
        """Get provider instance for model"""
        # Determine provider type from model
        provider_type = self._get_provider_for_model(model)
        
        # Check cache
        cache_key = f"{tenant_id}:{provider_type}"
        if cache_key in self.providers:
            return self.providers[cache_key]
            
        # Load from database
        provider_record = await self.db.llm_providers.find_one(
            tenant_id=tenant_id,
            provider_type=provider_type,
            is_active=True
        )
        
        if not provider_record:
            raise ProviderNotConfiguredError(
                f"Provider {provider_type} not configured for tenant"
            )
            
        # Decrypt API key
        api_key = self.fernet.decrypt(
            provider_record.encrypted_api_key.encode()
        ).decode()
        
        # Initialize provider
        provider_class = self.provider_classes[provider_type]
        provider = provider_class(
            api_key=api_key,
            **provider_record.config
        )
        
        # Cache for future use
        self.providers[cache_key] = provider
        
        return provider
        
    def _get_provider_for_model(self, model: str) -> str:
        """Determine provider type from model name"""
        if model.startswith("gpt"):
            return "openai"
        elif model.startswith("claude"):
            return "anthropic"
        elif model.startswith("gemini"):
            return "google"
        # Add more mappings as needed
        else:
            raise ValueError(f"Unknown model: {model}")
```

### Task 204: Short-Term Memory Integration
**Priority**: Medium  
**Effort**: 3 days  
**Description**: Implement 4-hour TTL conversation memory

#### STM Implementation
```python
# src/memory/short_term.py
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import json

class ShortTermMemory:
    """Short-term memory with 4-hour TTL"""
    
    def __init__(self, redis_client: Redis):
        self.redis = redis_client
        self.ttl = timedelta(hours=4)
        self.importance_threshold = 0.7
        
    async def store_context(
        self,
        conversation_id: UUID,
        context_type: str,
        content: str,
        importance: float = 0.5,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Store context in STM"""
        key = f"stm:{conversation_id}"
        
        entry = {
            "type": context_type,
            "content": content,
            "importance": importance,
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": metadata or {}
        }
        
        # Add to sorted set by importance
        await self.redis.zadd(
            key,
            {json.dumps(entry): importance}
        )
        
        # Set TTL
        await self.redis.expire(key, int(self.ttl.total_seconds()))
        
        # Trim to keep only top entries
        await self.redis.zremrangebyrank(key, 0, -21)  # Keep top 20
        
    async def get_context(
        self,
        conversation_id: UUID,
        min_importance: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """Get relevant context from STM"""
        key = f"stm:{conversation_id}"
        
        if min_importance is None:
            min_importance = self.importance_threshold
            
        # Get entries above importance threshold
        entries = await self.redis.zrevrangebyscore(
            key,
            "+inf",
            min_importance,
            withscores=True
        )
        
        contexts = []
        for entry_json, score in entries:
            entry = json.loads(entry_json)
            entry["score"] = score
            contexts.append(entry)
            
        return contexts
        
    async def extract_from_conversation(
        self,
        conversation_id: UUID,
        messages: List[Message]
    ) -> None:
        """Extract important context from messages"""
        # Use LLM to extract key information
        extraction_prompt = self._build_extraction_prompt(messages)
        
        # Get extraction from LLM
        extracted = await self.llm_service.extract_context(extraction_prompt)
        
        # Store each extracted piece
        for item in extracted:
            await self.store_context(
                conversation_id=conversation_id,
                context_type=item["type"],
                content=item["content"],
                importance=item["importance"]
            )
            
    def _build_extraction_prompt(self, messages: List[Message]) -> str:
        """Build prompt for context extraction"""
        conversation_text = "\n".join([
            f"{msg.role}: {msg.content}" for msg in messages[-10:]
        ])
        
        return f"""
        Extract important context from this conversation that should be remembered:
        
        {conversation_text}
        
        Identify:
        1. User preferences mentioned
        2. Important facts or constraints
        3. Goals or objectives
        4. Technical requirements
        
        Format as JSON array with type, content, and importance (0-1).
        """
```

#### STM Middleware
```python
# src/memory/middleware.py
class STMMiddleware:
    """Middleware to update STM during conversations"""
    
    def __init__(self, stm: ShortTermMemory):
        self.stm = stm
        self.extraction_interval = 5  # messages
        
    async def process_message(
        self,
        conversation_id: UUID,
        message: Message
    ) -> None:
        """Process message for STM extraction"""
        # Track user preferences
        if message.role == "user":
            await self._extract_preferences(conversation_id, message)
            
        # Periodic extraction
        if message.message_count % self.extraction_interval == 0:
            recent_messages = await self.db.messages.find(
                conversation_id=conversation_id,
                limit=self.extraction_interval,
                order_by="created_at DESC"
            )
            
            await self.stm.extract_from_conversation(
                conversation_id,
                recent_messages
            )
            
    async def _extract_preferences(
        self,
        conversation_id: UUID,
        message: Message
    ) -> None:
        """Extract preferences from user message"""
        # Simple pattern matching for preferences
        patterns = {
            "name_preference": r"call me (\w+)",
            "language_preference": r"(?:prefer|like|use) (\w+) (?:language|programming)",
            "style_preference": r"(?:be |more |less )(\w+)"
        }
        
        for pref_type, pattern in patterns.items():
            if match := re.search(pattern, message.content, re.IGNORECASE):
                await self.stm.store_context(
                    conversation_id=conversation_id,
                    context_type=pref_type,
                    content=match.group(1),
                    importance=0.9
                )
```

### Task 205: Basic UI for Conversations
**Priority**: Medium  
**Effort**: 4 days  
**Description**: Create basic conversation UI with model selection

#### Frontend Components
```typescript
// Frontend structure (React/Next.js)
// components/ConversationList.tsx
interface ConversationListProps {
  status?: 'active' | 'archived';
}

export const ConversationList: React.FC<ConversationListProps> = ({ status = 'active' }) => {
  const { conversations, loading } = useConversations(status);
  
  return (
    <div className="conversation-list">
      {conversations.map(conv => (
        <ConversationItem
          key={conv.id}
          conversation={conv}
          onClick={() => router.push(`/chat/${conv.id}`)}
        />
      ))}
      <NewConversationButton />
    </div>
  );
};

// components/ChatInterface.tsx
export const ChatInterface: React.FC<{ conversationId: string }> = ({ conversationId }) => {
  const { messages, sendMessage, streaming } = useChat(conversationId);
  const [input, setInput] = useState('');
  
  const handleSend = async () => {
    if (!input.trim() || streaming) return;
    
    await sendMessage(input);
    setInput('');
  };
  
  return (
    <div className="chat-interface">
      <ChatHeader conversation={conversation} />
      <MessageList messages={messages} streaming={streaming} />
      <TokenCounter used={conversation.totalTokens} limit={conversation.maxTokens} />
      <ChatInput
        value={input}
        onChange={setInput}
        onSend={handleSend}
        disabled={streaming}
      />
    </div>
  );
};

// hooks/useChat.ts
export const useChat = (conversationId: string) => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [streaming, setStreaming] = useState(false);
  const ws = useWebSocket();
  
  useEffect(() => {
    // Setup WebSocket handlers
    ws.on('assistant.content', (data) => {
      // Append to current streaming message
    });
    
    ws.on('assistant.complete', (data) => {
      setStreaming(false);
      // Update token counts
    });
  }, [ws]);
  
  const sendMessage = async (content: string) => {
    setStreaming(true);
    ws.send({
      type: 'chat.message',
      conversation_id: conversationId,
      content
    });
  };
  
  return { messages, sendMessage, streaming };
};
```

---

## Technical Specifications

### Database Migrations
```sql
-- Migration: 001_create_conversations_tables.sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Agent tables (NEW)
CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id), -- NULL for system agents
    team_id UUID REFERENCES teams(id), -- NULL for non-team agents
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(50) NOT NULL, -- general, specialist, coordinator, team
    definition JSONB NOT NULL, -- LangGraph JSON definition
    version INTEGER DEFAULT 1,
    is_system BOOLEAN DEFAULT false,
    is_active BOOLEAN DEFAULT true,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    -- Indexes
    INDEX idx_agents_tenant (tenant_id),
    INDEX idx_agents_team (team_id),
    INDEX idx_agents_type (type),
    INDEX idx_agents_system (is_system) WHERE is_system = true
);

-- Agent capabilities
CREATE TABLE agent_capabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    capability VARCHAR(100) NOT NULL, -- web_search, code_execution, etc.
    UNIQUE(agent_id, capability)
);

-- Agent tools
CREATE TABLE agent_tools (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    tool_id UUID NOT NULL REFERENCES tools(id),
    UNIQUE(agent_id, tool_id)
);

-- Main tables
CREATE TABLE conversations (
    -- ... as defined above with agent_id
);

CREATE TABLE messages (...);
CREATE TABLE conversation_checkpoints (...);
CREATE TABLE message_attachments (...);

-- Provider tables
CREATE TABLE llm_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    provider_type VARCHAR(50) NOT NULL,
    encrypted_api_key TEXT NOT NULL,
    config JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Team agent assignment
ALTER TABLE teams ADD COLUMN agent_id UUID REFERENCES agents(id);

-- Tenant default agent
ALTER TABLE tenants ADD COLUMN default_agent_id UUID REFERENCES agents(id);

-- Indexes
CREATE INDEX idx_llm_providers_tenant ON llm_providers(tenant_id);
CREATE INDEX idx_conversations_active ON conversations(tenant_id, user_id, status) WHERE status = 'active';
```

### API Endpoints Summary

#### Teams API
```
POST   /api/v1/teams                            # Create team
GET    /api/v1/teams                            # List user's teams
GET    /api/v1/teams/{id}                       # Get team details
PUT    /api/v1/teams/{id}                       # Update team
DELETE /api/v1/teams/{id}                       # Delete team

POST   /api/v1/teams/{id}/members               # Add member
GET    /api/v1/teams/{id}/members               # List members
PUT    /api/v1/teams/{id}/members/{uid}         # Update member role
DELETE /api/v1/teams/{id}/members/{uid}         # Remove member
```

#### Tenant API
```
GET    /api/v1/tenants/current                  # Get current tenant info
GET    /api/v1/tenants/current/usage            # Get usage statistics
PUT    /api/v1/tenants/current/settings         # Update settings (admin)
```

#### Conversations API
```
POST   /api/v1/conversations                    # Create conversation
GET    /api/v1/conversations                    # List conversations
GET    /api/v1/conversations/{id}               # Get conversation
PATCH  /api/v1/conversations/{id}/archive       # Archive conversation
DELETE /api/v1/conversations/{id}               # Delete conversation

POST   /api/v1/conversations/{id}/share         # Share conversation
GET    /api/v1/conversations/{id}/shares        # List shares
DELETE /api/v1/conversations/{id}/shares/{sid}  # Remove share

POST   /api/v1/conversations/{id}/messages      # Send message
GET    /api/v1/conversations/{id}/messages      # Get messages

GET    /api/v1/teams/{id}/conversations         # List team conversations
```

#### WebSocket
```
WS     /ws/chat?token={token}                   # WebSocket chat
```

#### LLM Providers API
```
POST   /api/v1/llm-providers                    # Add provider (admin)
GET    /api/v1/llm-providers                    # List providers
PUT    /api/v1/llm-providers/{id}               # Update provider
DELETE /api/v1/llm-providers/{id}               # Remove provider
POST   /api/v1/llm-providers/{id}/test          # Test provider
```

### WebSocket Events - Complete Production Schema

#### Connection Management
```javascript
// Client -> Server
{
  "type": "connection.init",
  "token": "jwt_token",
  "client_id": "unique_client_id",
  "version": "1.0"
}

{
  "type": "connection.heartbeat",
  "timestamp": "iso-datetime"
}

{
  "type": "connection.reconnect",
  "client_id": "unique_client_id",
  "last_event_id": "uuid"
}

// Server -> Client
{
  "type": "connection.ack",
  "status": "connected",
  "client_id": "unique_client_id",
  "server_version": "1.0",
  "capabilities": ["chat", "tools", "teams", "documents"]
}

{
  "type": "connection.error",
  "error": "invalid_token",
  "code": 4001,
  "retry_after": 5000
}
```

#### Channel Management
```javascript
// Client -> Server
{
  "type": "channel.subscribe",
  "channels": [
    {"type": "conversation", "id": "conv_uuid"},
    {"type": "team", "id": "team_uuid"},
    {"type": "document", "id": "doc_uuid"}
  ]
}

{
  "type": "channel.unsubscribe",
  "channels": ["conv_uuid", "team_uuid"]
}

// Server -> Client
{
  "type": "channel.subscribed",
  "channel": {"type": "conversation", "id": "conv_uuid"},
  "current_state": {} // Initial state snapshot
}

{
  "type": "channel.presence",
  "channel": {"type": "team", "id": "team_uuid"},
  "users": [
    {"id": "user1", "status": "active", "activity": "viewing"},
    {"id": "user2", "status": "typing", "activity": "editing"}
  ]
}
```

#### Chat & Conversation Events
```javascript
// Client -> Server
{
  "type": "chat.message",
  "conversation_id": "uuid",
  "content": "message",
  "attachments": [
    {"id": "attach_id", "type": "image", "url": "s3://..."}
  ],
  "metadata": {
    "client_timestamp": "iso-datetime",
    "reply_to": "message_id"
  }
}

{
  "type": "chat.typing",
  "conversation_id": "uuid",
  "is_typing": true
}

{
  "type": "chat.configure",
  "conversation_id": "uuid",
  "config": {
    "model": "gpt-4-turbo",
    "temperature": 0.7,
    "max_tokens": 4096,
    "top_p": 0.9,
    "stop_sequences": ["\\n\\n"],
    "system_prompt": "custom instructions"
  }
}

{
  "type": "chat.regenerate",
  "conversation_id": "uuid",
  "message_id": "uuid",
  "config_override": {} // Optional config for this regeneration
}

// Server -> Client
{
  "type": "message.received",
  "message_id": "uuid",
  "conversation_id": "uuid",
  "timestamp": "iso-datetime",
  "sequence": 1234
}

{
  "type": "assistant.start",
  "conversation_id": "uuid",
  "message_id": "uuid",
  "model": "gpt-4-turbo",
  "estimated_time": 2000 // ms
}

{
  "type": "assistant.content",
  "message_id": "uuid",
  "content": "chunk",
  "tokens_used": 123,
  "chunk_index": 5
}

{
  "type": "assistant.thinking",
  "message_id": "uuid",
  "status": "analyzing_context" // or "searching_memory", "preparing_response"
}

{
  "type": "assistant.complete",
  "message_id": "uuid",
  "total_tokens": 456,
  "prompt_tokens": 123,
  "completion_tokens": 333,
  "cost": 0.0123,
  "duration_ms": 2341,
  "finish_reason": "stop" // or "length", "tool_calls"
}

{
  "type": "conversation.updated",
  "conversation_id": "uuid",
  "updates": {
    "title": "New Title",
    "total_tokens": 1234,
    "checkpoint_created": true
  }
}
```

#### Tool/Function Calling Events
```javascript
// Server -> Client
{
  "type": "tool.call.start",
  "message_id": "uuid",
  "tool_call_id": "call_uuid",
  "tool_name": "search_documents",
  "arguments": {
    "query": "project requirements",
    "limit": 10
  }
}

{
  "type": "tool.call.progress",
  "tool_call_id": "call_uuid",
  "status": "searching",
  "progress": 0.45,
  "message": "Searching through 1,234 documents..."
}

{
  "type": "tool.call.complete",
  "tool_call_id": "call_uuid",
  "result": {
    "success": true,
    "data": [...],
    "execution_time_ms": 234
  }
}

{
  "type": "tool.call.error",
  "tool_call_id": "call_uuid",
  "error": {
    "code": "TOOL_TIMEOUT",
    "message": "Tool execution timed out",
    "details": {}
  }
}

// Client -> Server (for interactive tools)
{
  "type": "tool.call.response",
  "tool_call_id": "call_uuid",
  "user_input": "approved" // For tools requiring user confirmation
}
```

#### File Upload & Attachments
```javascript
// Client -> Server
{
  "type": "file.upload.request",
  "file_metadata": {
    "name": "document.pdf",
    "size": 1048576,
    "mime_type": "application/pdf",
    "checksum": "sha256:..."
  },
  "purpose": "conversation_attachment" // or "knowledge_base", "team_document"
}

{
  "type": "file.chunk",
  "upload_id": "upload_uuid",
  "chunk_index": 0,
  "total_chunks": 10,
  "data": "base64_encoded_chunk"
}

// Server -> Client
{
  "type": "file.upload.authorized",
  "upload_id": "upload_uuid",
  "upload_url": "presigned_url", // For direct S3 upload
  "method": "direct" // or "chunked"
}

{
  "type": "file.upload.progress",
  "upload_id": "upload_uuid",
  "progress": 0.75,
  "bytes_received": 786432
}

{
  "type": "file.upload.complete",
  "upload_id": "upload_uuid",
  "file_id": "file_uuid",
  "url": "https://...",
  "processing_status": "pending" // For documents needing processing
}
```

#### Team Collaboration Events
```javascript
// Server -> Client
{
  "type": "team.activity",
  "team_id": "team_uuid",
  "activity": {
    "type": "conversation_created",
    "user": {"id": "user_id", "name": "John"},
    "data": {"conversation_id": "conv_uuid", "title": "New Discussion"}
  }
}

{
  "type": "team.presence.update",
  "team_id": "team_uuid",
  "user_id": "user_uuid",
  "status": "active", // or "away", "busy", "offline"
  "activity": {
    "type": "editing_document",
    "document_id": "doc_uuid",
    "location": "section_3"
  }
}

{
  "type": "team.notification",
  "team_id": "team_uuid",
  "notification": {
    "id": "notif_uuid",
    "type": "mention",
    "from_user": "user_uuid",
    "message": "@you check this out",
    "context": {"conversation_id": "conv_uuid"}
  }
}
```

#### Document Collaboration Events
```javascript
// Client -> Server
{
  "type": "document.edit",
  "document_id": "doc_uuid",
  "operation": {
    "type": "insert",
    "position": 1234,
    "content": "new text",
    "attributes": {"bold": true}
  },
  "revision": 45
}

{
  "type": "document.cursor",
  "document_id": "doc_uuid",
  "position": 1234,
  "selection": {"start": 1234, "end": 1250}
}

// Server -> Client
{
  "type": "document.sync",
  "document_id": "doc_uuid",
  "operations": [...], // Operational Transform patches
  "revision": 46,
  "author": "user_uuid"
}

{
  "type": "document.cursors",
  "document_id": "doc_uuid",
  "cursors": [
    {"user_id": "user1", "position": 100, "color": "#FF5733"},
    {"user_id": "user2", "position": 250, "color": "#33FF57"}
  ]
}

{
  "type": "document.ai.suggestion",
  "document_id": "doc_uuid",
  "suggestion": {
    "id": "sug_uuid",
    "type": "completion",
    "position": 1234,
    "content": "suggested text",
    "confidence": 0.85
  }
}
```

#### Agent Interaction Events
```javascript
// Client -> Server
{
  "type": "agent.invoke",
  "agent_id": "agent_uuid",
  "input": "analyze this data",
  "context": {
    "conversation_id": "conv_uuid",
    "attachments": ["file_uuid"]
  },
  "config": {
    "timeout": 30000,
    "memory_access": true
  }
}

// Server -> Client
{
  "type": "agent.status",
  "agent_id": "agent_uuid",
  "execution_id": "exec_uuid",
  "status": "running",
  "current_node": "data_analysis",
  "progress": 0.3
}

{
  "type": "agent.output",
  "agent_id": "agent_uuid",
  "execution_id": "exec_uuid",
  "output": {
    "type": "intermediate",
    "node": "data_analysis",
    "data": {...}
  }
}

{
  "type": "agent.complete",
  "agent_id": "agent_uuid",
  "execution_id": "exec_uuid",
  "result": {...},
  "usage": {
    "total_tokens": 1234,
    "execution_time_ms": 5678,
    "tools_called": ["search", "calculate"]
  }
}
```

#### Memory & Preference Events
```javascript
// Client -> Server
{
  "type": "preference.update",
  "preferences": {
    "display_name": "Timmy",
    "language": "rust",
    "style": "concise"
  }
}

// Server -> Client
{
  "type": "memory.extracted",
  "conversation_id": "conv_uuid",
  "memories": [
    {"type": "fact", "content": "User prefers Rust", "importance": 0.9},
    {"type": "preference", "content": "Likes concise answers", "importance": 0.8}
  ]
}

{
  "type": "memory.checkpoint",
  "conversation_id": "conv_uuid",
  "checkpoint_id": "check_uuid",
  "summary": "Discussed project architecture...",
  "key_points": ["microservices", "rust", "kubernetes"]
}
```

#### Error & Status Events
```javascript
// Server -> Client
{
  "type": "error",
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests",
    "details": {
      "limit": 100,
      "window": "1h",
      "retry_after": 3600
    }
  },
  "context": {
    "request_type": "chat.message",
    "conversation_id": "conv_uuid"
  }
}

{
  "type": "system.announcement",
  "level": "warning", // or "info", "critical"
  "message": "Scheduled maintenance in 30 minutes",
  "action_required": false
}

{
  "type": "quota.warning",
  "resource": "tokens",
  "usage": {
    "used": 90000,
    "limit": 100000,
    "percentage": 90
  },
  "reset_at": "iso-datetime"
}
```

### Additional Required API Endpoints

#### Agent Management API
```
POST   /api/v1/agents                           # Create agent
GET    /api/v1/agents                           # List agents
GET    /api/v1/agents/{id}                      # Get agent details
PUT    /api/v1/agents/{id}                      # Update agent
DELETE /api/v1/agents/{id}                      # Delete agent
POST   /api/v1/agents/{id}/test                 # Test agent
GET    /api/v1/agents/{id}/executions           # List agent executions

POST   /api/v1/teams/{id}/agent                 # Assign agent to team
GET    /api/v1/teams/{id}/agent                 # Get team agent
```

#### Memory & Preferences API
```
GET    /api/v1/users/me/preferences             # Get user preferences
PUT    /api/v1/users/me/preferences             # Update preferences
DELETE /api/v1/users/me/preferences/{key}       # Delete preference

GET    /api/v1/memory/search                    # Search memories
POST   /api/v1/memory/extract                   # Manual memory extraction
GET    /api/v1/conversations/{id}/memories      # Get conversation memories
DELETE /api/v1/conversations/{id}/memories/{id} # Delete memory

GET    /api/v1/conversations/{id}/checkpoints   # List checkpoints
POST   /api/v1/conversations/{id}/checkpoint    # Create checkpoint
```

#### Document Management API
```
POST   /api/v1/documents                        # Create/upload document
GET    /api/v1/documents                        # List documents
GET    /api/v1/documents/{id}                   # Get document
PUT    /api/v1/documents/{id}                   # Update document
DELETE /api/v1/documents/{id}                   # Delete document

POST   /api/v1/documents/{id}/share             # Share document
GET    /api/v1/documents/{id}/shares            # List shares
DELETE /api/v1/documents/{id}/shares/{sid}      # Remove share

POST   /api/v1/documents/{id}/embed             # Generate embeddings
GET    /api/v1/documents/{id}/versions          # List versions
GET    /api/v1/documents/{id}/related           # Get related docs

POST   /api/v1/teams/{id}/documents             # Upload to team
GET    /api/v1/teams/{id}/documents             # List team documents
```

#### Tool & MCP Integration API
```
POST   /api/v1/tools                            # Register tool
GET    /api/v1/tools                            # List tools
GET    /api/v1/tools/{id}                       # Get tool details
PUT    /api/v1/tools/{id}                       # Update tool
DELETE /api/v1/tools/{id}                       # Delete tool
POST   /api/v1/tools/{id}/test                  # Test tool

POST   /api/v1/mcp-servers                      # Register MCP server
GET    /api/v1/mcp-servers                      # List MCP servers
GET    /api/v1/mcp-servers/{id}/tools           # List server tools
POST   /api/v1/mcp-servers/{id}/connect         # Connect to server
```

#### Knowledge Graph API
```
GET    /api/v1/knowledge/search                 # Search knowledge graph
GET    /api/v1/knowledge/entities/{id}          # Get entity details
GET    /api/v1/knowledge/relationships          # Query relationships
POST   /api/v1/knowledge/query                  # Custom graph query

GET    /api/v1/documents/{id}/graph             # Get document graph
GET    /api/v1/users/{id}/graph                 # Get user knowledge graph
```

#### Prompt Management API
```
POST   /api/v1/prompts                          # Create prompt template
GET    /api/v1/prompts                          # List prompts
GET    /api/v1/prompts/{id}                     # Get prompt
PUT    /api/v1/prompts/{id}                     # Update prompt
DELETE /api/v1/prompts/{id}                     # Delete prompt

POST   /api/v1/prompts/{id}/share               # Share prompt
GET    /api/v1/prompts/{id}/versions            # List versions
POST   /api/v1/prompts/{id}/fork                # Fork prompt

GET    /api/v1/teams/{id}/prompts               # List team prompts
```

#### File Storage API
```
POST   /api/v1/files/upload-url                 # Get presigned upload URL
POST   /api/v1/files                            # Upload file metadata
GET    /api/v1/files/{id}                       # Get file info
DELETE /api/v1/files/{id}                       # Delete file
GET    /api/v1/files/{id}/download-url          # Get download URL

POST   /api/v1/files/{id}/process               # Process file (OCR, etc)
GET    /api/v1/files/{id}/status                # Get processing status
```

#### Analytics & Usage API
```
GET    /api/v1/analytics/usage                  # Get usage stats
GET    /api/v1/analytics/costs                  # Get cost breakdown
GET    /api/v1/analytics/activity               # Get activity logs
GET    /api/v1/analytics/trends                 # Get usage trends

GET    /api/v1/teams/{id}/analytics             # Team analytics
GET    /api/v1/users/{id}/analytics             # User analytics
```

---

## Success Criteria

### Functional Requirements
- [x] Users can create and manage conversations
- [x] Messages stream in real-time via WebSocket
- [x] Token usage tracked and enforced
- [x] Costs calculated and displayed
- [x] Auto-title generation works
- [x] Conversation archiving implemented
- [x] STM extracts and stores context
- [x] Model selection per conversation

### Performance Requirements
- [ ] Message latency < 100ms
- [ ] Streaming starts < 500ms
- [ ] WebSocket connection stable
- [ ] Token counting accurate
- [ ] 1000+ concurrent conversations

### Business Logic Requirements
- [x] Token limits enforced
- [x] Cost tracking accurate
- [x] Checkpoints created every 50 messages
- [x] User preferences applied
- [x] Tenant limits respected
- [x] Rate limiting works

### Security Requirements
- [x] API keys encrypted at rest
- [x] Conversations tenant-isolated
- [x] User access validated
- [x] WebSocket authentication secure
- [x] No credential leakage

---

## Testing Plan

### Unit Tests
- Conversation service logic
- Message service operations
- Token counting accuracy
- Cost calculations
- STM operations
- Provider implementations

### Integration Tests
- End-to-end conversation flow
- WebSocket message flow
- Provider switching
- Token limit enforcement
- Checkpoint creation

### Load Tests
- Concurrent conversations
- Message throughput
- WebSocket scalability
- Database query performance

---

## Definition of Done

- [ ] All database migrations applied
- [ ] API endpoints implemented and documented
- [ ] WebSocket handlers complete
- [ ] Business logic fully integrated
- [ ] OpenAI provider working
- [ ] STM extracting context
- [ ] Basic UI functional
- [ ] Unit tests passing (>80% coverage)
- [ ] Integration tests passing
- [ ] Performance benchmarks met
- [ ] Security review passed
- [ ] Documentation updated

---

## Next Sprint Preview

**Sprint 201: Agent System Foundation**
- LangGraph integration
- Dynamic agent loading
- Agent builder UI
- Tool system basics
- Agent CRUD APIs

This sprint establishes the conversation foundation needed before implementing the agent system in the next sprint.

---

## Summary of Changes

### Extended Sprint Scope
The sprint has been extended from 4 to 5 weeks to include essential CRUD APIs:

1. **Week 1: Foundation CRUD APIs** (NEW)
   - Teams management API (full CRUD + members)
   - Basic tenant settings API
   - Prepare for team-aware conversations

2. **Week 2: Conversation System**
   - Team-aware conversations
   - Sharing functionality
   - Business logic embedded in services

3. **Week 3: Message Streaming**
   - WebSocket implementation
   - Token tracking
   - Real-time updates

4. **Week 4: LLM Provider System**
   - Start with OpenAI
   - Provider abstraction
   - Secure key storage

5. **Week 5: STM & UI**
   - Short-term memory
   - Basic conversation UI
   - Team selector in UI

### Key Additions
- **Team Support**: All conversations can be personal or team-based
- **Sharing**: Conversations can be shared with users or teams
- **Access Control**: Proper permission checking for team resources
- **Business Rules**: Team limits, member validation, audit logging

### API Design Philosophy
- Build CRUD as features need them
- Embed business logic in service layer
- Consistent error handling
- Proper audit trails
- Team-aware from the start