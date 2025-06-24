# Task 202: Conversation System with Agent Integration

## Task Overview
**Sprint**: 200  
**Priority**: Critical  
**Effort**: 4 days  
**Dependencies**: 
- Task 201 (Agent System Foundation) must be complete
- Teams API (Task 200) should be available

## ⚠️ IMPORTANT INSTRUCTIONS

### Before Starting Development:
1. **ALWAYS check existing database models** in `/docs/database/DATABASE_MODELS_V5_COMPLETE.md`
2. **NEVER create new models** without verifying if they already exist
3. **ALWAYS check existing API endpoints** before creating new ones
4. **ALWAYS check existing factories and services** before creating new ones
5. **NO MOCKS** - implement production-ready code
6. **NO PSEUDOCODE** - complete all implementations
7. **NO TODOs** - finish all tasks completely

### Required Reading:
- `/docs/database/DATABASE_MODELS_V5_COMPLETE.md` - Database models
- `/docs/architecture/LANGGRAPH_INTEGRATION.md` - Agent architecture
- `/CLAUDE.md` - Project conventions
- Previous task outputs (Task 201)

## Task Description
Integrate the conversation system with LangGraph agents. Every conversation must be bound to an agent, and all AI responses flow through the agent system rather than direct LLM calls.

## Database Schema Updates

### 1. Verify Existing Tables:
```bash
# Check conversations table structure
grep -A 20 "conversations" docs/database/DATABASE_MODELS_V5_COMPLETE.md
```

### 2. Add Agent Binding to Conversations:
```sql
-- Add agent_id to conversations if not exists
ALTER TABLE conversations 
ADD COLUMN agent_id UUID NOT NULL REFERENCES agents(id);

-- Add indexes
CREATE INDEX idx_conversations_agent ON conversations(agent_id);
```

### 3. Update Team Tables:
```sql
-- Add default agent to teams
ALTER TABLE teams 
ADD COLUMN agent_id UUID REFERENCES agents(id);

-- Add default agent to tenants
ALTER TABLE tenants 
ADD COLUMN default_agent_id UUID REFERENCES agents(id);
```

## Implementation Components

### 1. Enhanced Conversation Service
```python
# src/services/conversation_service.py
```

Key changes:
- Add `agent_manager` dependency
- Implement agent selection logic:
  - Team conversations → Team agent
  - Personal conversations → User preference or tenant default
- Bind agent to conversation on creation
- Store agent metadata in conversation

Agent selection priority:
1. Explicitly provided agent_id
2. Team's assigned agent (if team conversation)
3. User's preferred agent
4. Tenant's default agent
5. System default agent

### 2. Message Service with Agent Execution
```python
# src/services/message_service.py
```

Replace direct LLM calls with agent execution:
- Remove `llm_service` dependency
- Add `agent_executor` dependency
- Prepare agent input with full context
- Stream agent execution events
- Transform agent events to WebSocket events

Agent input structure:
```python
{
    "conversation_id": "uuid",
    "user_id": "uuid",
    "message": "current message",
    "history": [...],  # Previous messages
    "preferences": {...},  # User preferences
    "stm_context": {...},  # Short-term memory
    "team_id": "uuid"  # If team conversation
}
```

### 3. Update Conversation API
```python
# src/api/v1/conversations/router.py
```

Changes to endpoints:
- Add `agent_id` to create conversation request
- Include agent info in conversation response
- Add endpoint to change conversation agent

New endpoint:
```
PUT /api/v1/conversations/{id}/agent
```

### 4. Update Conversation Schemas
```python
# src/api/v1/conversations/schemas.py
```

Updated schemas:
```python
class CreateConversationRequest(BaseModel):
    agent_id: Optional[UUID] = None
    title: Optional[str] = None
    team_id: Optional[UUID] = None
    
class ConversationResponse(BaseModel):
    id: UUID
    title: str
    agent_id: UUID
    agent_name: str
    agent_type: str
    # ... other fields
```

### 5. WebSocket Handler Updates
```python
# src/api/v1/websocket/chat.py
```

Handle new event types from agents:
- `agent.thinking` events
- `tool.call.*` events
- Enhanced error handling for agent failures

## Business Logic Implementation

### 1. Conversation Creation Flow:
```
1. Receive create request
2. Determine appropriate agent
3. Validate agent access
4. Get agent's default model
5. Create conversation with agent binding
6. Initialize STM for conversation
7. Return conversation with agent info
```

### 2. Message Processing Flow:
```
1. Add user message to conversation
2. Load conversation's agent
3. Build execution context
4. Stream agent execution
5. Transform events to WebSocket
6. Save assistant response
7. Update conversation metrics
```

### 3. Agent Access Control:
- Users can only use agents available to their tenant
- Team agents restricted to team members
- System agents available to all
- Private agents restricted to creators

## Event Streaming Updates

### From Agent to WebSocket:
```
Agent Event              → WebSocket Event
─────────────────────────────────────────
llm_start               → assistant.start
llm_token               → assistant.content
llm_complete            → assistant.complete
tool_start              → tool.call.start
tool_complete           → tool.call.complete
agent_thinking          → assistant.thinking
error                   → error
```

## Testing Requirements

### Unit Tests:
- Agent selection logic
- Event transformation
- Context building
- Error handling

### Integration Tests:
- Full conversation flow with agent
- Agent switching mid-conversation
- Team agent assignment
- Streaming integrity

### End-to-End Tests:
- Create conversation → Send message → Get response
- Tool execution within conversation
- Memory access during conversation

## Migration Considerations

For existing conversations without agents:
1. Create migration script
2. Assign default agent to existing conversations
3. Update conversation metadata
4. Test with production data subset

## Success Criteria

- [ ] All conversations bound to agents
- [ ] No direct LLM calls in conversation flow
- [ ] Agent events properly transformed
- [ ] Team agent assignment working
- [ ] User preferences respected
- [ ] Streaming maintains low latency
- [ ] Error handling comprehensive
- [ ] Existing tests updated

## Performance Considerations

1. **Agent Caching**:
   - Cache agents used in active conversations
   - Preload team agents
   - Monitor cache hit rates

2. **Streaming Performance**:
   - Minimize event transformation overhead
   - Efficient buffer management
   - Monitor event latency

3. **Context Building**:
   - Efficient history retrieval
   - Parallel STM and preference loading
   - Limit context size appropriately

## Error Scenarios

Handle these error cases:
- Agent not found
- Agent not accessible
- Agent execution timeout
- Tool execution failure
- Memory access failure
- Token limit exceeded
- Provider unavailable

## Rollback Plan

If issues arise:
1. Feature flag for agent integration
2. Fallback to direct LLM calls
3. Maintain backward compatibility
4. Gradual rollout by tenant