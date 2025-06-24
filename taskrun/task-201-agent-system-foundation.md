# Task 201: Agent System Foundation

## Task Overview
**Sprint**: 200  
**Priority**: Critical  
**Effort**: 5 days  
**Dependencies**: 
- Database models exist
- LangGraph library available

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
- `/docs/architecture/LANGGRAPH_INTEGRATION.md` - LangGraph architecture
- `/docs/database/DATABASE_MODELS_V5_COMPLETE.md` - Database models
- `/docs/CONCEPT_SUMMARY.md` - Platform vision
- `/CLAUDE.md` - Project conventions

## Architecture Overview

```
Client ↔ WebSocket ↔ AgentExecutor ↔ LangGraph Agent ↔ LLM Provider
                                          ↓
                                    Tools, Memory, MCP
```

## Task Description
Implement the foundation for the LangGraph agent system that mediates between conversations and LLM providers. This includes the agent loader, executor, and manager components.

## Database Schema Requirements

### 1. Check Existing Agent Tables:
```bash
# Check if agents table exists
grep -n "agents" docs/database/DATABASE_MODELS_V5_COMPLETE.md

# If not exists, create migration
```

### 2. Required Tables:
```sql
-- agents table
CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    team_id UUID REFERENCES teams(id),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    type VARCHAR(50) NOT NULL,
    definition JSONB NOT NULL,
    version INTEGER DEFAULT 1,
    is_system BOOLEAN DEFAULT false,
    is_active BOOLEAN DEFAULT true,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- agent_capabilities table
CREATE TABLE agent_capabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    capability VARCHAR(100) NOT NULL,
    UNIQUE(agent_id, capability)
);

-- agent_tools table
CREATE TABLE agent_tools (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    tool_id UUID NOT NULL REFERENCES tools(id),
    UNIQUE(agent_id, tool_id)
);
```

## Implementation Components

### 1. Dynamic Agent Loader
```python
# src/agents/loader.py
```

Key responsibilities:
- Load agent definitions from JSON
- Validate agent schemas
- Create LangGraph instances
- Node factory implementations
- Template rendering

Required node types:
- `input` - Entry point
- `llm` - LLM calls
- `tool` - Tool execution
- `condition` - Routing logic
- `memory` - Memory operations
- `output` - Exit point

### 2. Agent Executor
```python
# src/agents/executor.py
```

Key methods:
- `stream_execution()` - Main execution with event streaming
- `_get_or_load_agent()` - Agent caching
- Event transformation from LangGraph to platform events

Event types to handle:
- `on_llm_start` → `llm_start`
- `on_llm_new_token` → `llm_token`
- `on_llm_end` → `llm_complete`
- `on_tool_start` → `tool_start`
- `on_tool_end` → `tool_complete`

### 3. Agent Manager
```python
# src/agents/manager.py
```

Key methods:
- `get_agent()` - With access control
- `get_default_agent()` - User/tenant defaults
- `get_team_agent()` - Team agent assignment
- `create_agent()` - New agent creation
- `update_agent()` - Agent updates
- `validate_agent_access()` - Permission checks

### 4. Execution Context
```python
# src/agents/context.py
```

Context should include:
- `tenant_id` - For isolation
- `agent_id` - Current agent
- `user_id` - Executing user
- `llm_router` - LLM provider access
- `tool_registry` - Available tools
- `memory_manager` - Memory access

### 5. Agent Event Types
```python
# src/agents/events.py
```

Define event classes:
- `AgentEvent` - Base class
- `LLMEvent` - LLM interactions
- `ToolEvent` - Tool executions
- `MemoryEvent` - Memory operations
- `ErrorEvent` - Error handling

## Agent Definition Schema

### JSON Schema Example:
```json
{
  "id": "uuid",
  "name": "General Assistant",
  "type": "general",
  "graph": {
    "nodes": [...],
    "edges": [...],
    "entry_point": "input"
  },
  "config": {
    "llm_provider": "openai",
    "default_model": "gpt-4",
    "temperature": 0.7,
    "max_tokens": 4000
  },
  "tools": ["web_search", "calculator"],
  "capabilities": ["web_search", "memory_access"]
}
```

## Integration Points

### 1. LLM Provider Integration:
- Agents use `LLMProviderManager` for model access
- Support provider switching per node
- Token tracking per execution

### 2. Tool Registry Integration:
- Dynamic tool loading
- Permission-based tool access
- Sandboxed execution

### 3. Memory Integration:
- STM access during execution
- LTM queries for context
- Memory updates post-execution

## Default System Agents

Create these system agents:
1. **General Assistant** - Basic conversational agent
2. **Research Agent** - Web search and analysis
3. **Code Assistant** - Programming help
4. **Team Coordinator** - Team collaboration

## Testing Requirements

### Unit Tests:
- Agent loading from JSON
- Node factory creation
- Event transformation
- Context management

### Integration Tests:
- Full agent execution
- Tool integration
- Memory access
- Error handling

## Success Criteria

- [x] Agent loader parses JSON definitions
- [x] LangGraph instances created successfully
- [x] Events stream properly to WebSocket
- [x] LLM calls routed through providers
- [x] Tools execute within agents
- [x] Memory accessible during execution
- [x] Caching improves performance
- [x] Error handling robust

## Performance Considerations

1. **Agent Caching**: 
   - Cache compiled agents in memory
   - LRU eviction policy
   - Tenant-based cache keys

2. **Streaming Optimization**:
   - Minimal event transformation overhead
   - Efficient token streaming
   - Backpressure handling

3. **Resource Limits**:
   - Execution timeouts
   - Memory limits
   - Token limits per execution

## Security Considerations

1. **Agent Validation**:
   - Schema validation before loading
   - Prevent arbitrary code execution
   - Validate tool permissions

2. **Tenant Isolation**:
   - Agents scoped to tenants
   - No cross-tenant access
   - Audit all executions

3. **Tool Sandboxing**:
   - Execute tools in isolation
   - Resource limits enforced
   - No file system access unless permitted