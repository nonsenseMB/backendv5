# Agents API

The Agents API provides endpoints for creating, managing, and executing AI agents powered by LangGraph.

## Endpoints

### Create Agent
`POST /api/v1/agents`

Create a new AI agent with a custom graph definition.

**Request Body:**
```json
{
  "name": "research_assistant",
  "display_name": "Research Assistant",
  "description": "AI agent for research tasks",
  "agent_type": "specialist",
  "specialization": "research",
  "graph_definition": {
    "nodes": [...],
    "edges": [...],
    "entry_point": "input"
  },
  "system_prompt": "You are a helpful research assistant...",
  "capabilities": ["web_search", "memory_access"],
  "tool_ids": ["uuid1", "uuid2"],
  "is_public": false,
  "team_id": null,
  "temperature": 0.7
}
```

**Response:**
```json
{
  "id": "agent-uuid",
  "name": "research_assistant",
  "display_name": "Research Assistant",
  "description": "AI agent for research tasks",
  "agent_type": "specialist",
  "specialization": "research",
  "capabilities": ["web_search", "memory_access"],
  "tool_ids": ["uuid1", "uuid2"],
  "is_public": false,
  "is_active": true,
  "created_by": "user-uuid",
  "created_at": "2024-01-20T12:00:00Z",
  "updated_at": "2024-01-20T12:00:00Z",
  "total_conversations": 0,
  "satisfaction_score": 0.0,
  "avg_response_time_ms": 0
}
```

### List Agents
`GET /api/v1/agents`

List all agents accessible to the current user.

**Query Parameters:**
- `include_inactive` (boolean): Include inactive agents
- `include_team_agents` (boolean): Include team agents
- `limit` (integer): Maximum results (max: 100)
- `offset` (integer): Pagination offset

**Response:**
```json
{
  "agents": [...],
  "total": 25,
  "limit": 100,
  "offset": 0
}
```

### Get Agent Details
`GET /api/v1/agents/{agent_id}`

Get detailed information about a specific agent.

**Response:**
```json
{
  "id": "agent-uuid",
  "name": "research_assistant",
  "display_name": "Research Assistant",
  "description": "AI agent for research tasks",
  "agent_type": "specialist",
  "specialization": "research",
  "graph_definition": {...},
  "system_prompt": "You are a helpful research assistant...",
  "temperature": 0.7,
  "model_preferences": {},
  "allowed_roles": ["admin", "member"],
  "tags": ["research", "ai"],
  // ... other fields
}
```

### Update Agent
`PATCH /api/v1/agents/{agent_id}`

Update an agent's configuration.

**Request Body:**
```json
{
  "display_name": "Updated Research Assistant",
  "description": "Updated description",
  "graph_definition": {...},
  "system_prompt": "Updated prompt",
  "capabilities": ["web_search"],
  "tool_ids": ["uuid1"],
  "is_active": true,
  "is_public": true,
  "temperature": 0.8
}
```

### Delete Agent
`DELETE /api/v1/agents/{agent_id}`

Delete an agent. System agents cannot be deleted.

**Response:** 204 No Content

### Execute Agent
`POST /api/v1/agents/{agent_id}/execute`

Execute an agent with a user message.

**Request Body:**
```json
{
  "message": "Research the latest AI developments",
  "context": {
    "previous_topic": "machine learning"
  },
  "stream": true
}
```

**Response (Non-streaming):**
```json
{
  "execution_id": "exec-uuid",
  "status": "completed",
  "message": "Agent execution completed"
}
```

**Response (Streaming):**
Server-Sent Events stream with events:
```
data: {"event_type": "agent_start", "timestamp": "2024-01-20T12:00:00Z", "agent_id": "...", "metadata": {}}

data: {"event_type": "llm_token", "timestamp": "2024-01-20T12:00:01Z", "agent_id": "...", "metadata": {"token": "The"}}

data: {"event_type": "agent_complete", "timestamp": "2024-01-20T12:00:10Z", "agent_id": "...", "metadata": {"final_output": "..."}}
```

### Add Agent Memory
`POST /api/v1/agents/{agent_id}/memories`

Add a memory entry to an agent.

**Request Body:**
```json
{
  "memory_type": "learning",
  "content": "User prefers concise responses",
  "conversation_id": "conv-uuid",
  "confidence": 0.8,
  "source": "user_feedback"
}
```

**Response:**
```json
{
  "id": "memory-uuid",
  "agent_id": "agent-uuid",
  "memory_type": "learning",
  "content": "User prefers concise responses",
  "confidence": 0.8,
  "usefulness_score": 0.0,
  "application_count": 0,
  "source": "user_feedback",
  "is_active": true,
  "created_at": "2024-01-20T12:00:00Z",
  "last_applied_at": null
}
```

### Get Agent Memories
`GET /api/v1/agents/{agent_id}/memories`

Retrieve memories for an agent.

**Query Parameters:**
- `memory_type` (string): Filter by memory type
- `limit` (integer): Maximum results (max: 100)

**Response:**
```json
[
  {
    "id": "memory-uuid",
    "agent_id": "agent-uuid",
    "memory_type": "learning",
    "content": "User prefers concise responses",
    "confidence": 0.8,
    "usefulness_score": 0.7,
    "application_count": 5,
    "source": "user_feedback",
    "is_active": true,
    "created_at": "2024-01-20T12:00:00Z",
    "last_applied_at": "2024-01-20T13:00:00Z"
  }
]
```

### Validate Agent Definition
`POST /api/v1/agents/validate`

Validate an agent graph definition without creating an agent.

**Request Body:**
```json
{
  "graph_definition": {
    "nodes": [...],
    "edges": [...],
    "entry_point": "input"
  }
}
```

**Response:**
```json
{
  "valid": true,
  "errors": [],
  "warnings": ["Graph has many nodes, consider simplifying"]
}
```

### Clone Agent
`POST /api/v1/agents/{agent_id}/clone`

Create a copy of an existing agent.

**Request Body:**
```json
{
  "name": "cloned_agent",
  "display_name": "Cloned Research Assistant",
  "description": "Clone of research assistant",
  "team_id": null
}
```

### Export Agent
`GET /api/v1/agents/{agent_id}/export`

Export an agent configuration for backup or sharing.

**Query Parameters:**
- `include_memories` (boolean): Include agent memories

**Response:**
```json
{
  "agent": {...},
  "graph_definition": {...},
  "memories": [...],
  "version": "1.0.0",
  "exported_at": "2024-01-20T12:00:00Z"
}
```

### Create Default Agents
`POST /api/v1/agents/default`

Create default system agents for the tenant (admin only).

**Response:**
```json
[
  {
    "id": "agent-uuid-1",
    "name": "qa_agent_tenant-uuid",
    "display_name": "Q&A Assistant",
    // ...
  },
  {
    "id": "agent-uuid-2",
    "name": "research_agent_tenant-uuid",
    "display_name": "Research Assistant",
    // ...
  }
]
```

## Rate Limits

- Agent creation: 10 per hour
- Agent updates: 20 per hour
- Agent deletion: 5 per hour
- Agent execution: 100 per hour
- Agent cloning: 5 per hour

## Error Responses

### 400 Bad Request
```json
{
  "detail": "Invalid graph definition: Unknown node type: custom"
}
```

### 403 Forbidden
```json
{
  "detail": "Cannot modify this agent"
}
```

### 404 Not Found
```json
{
  "detail": "Agent not found"
}
```

### 429 Too Many Requests
```json
{
  "detail": "Rate limit exceeded",
  "retry_after": 3600
}
```

### 500 Internal Server Error
```json
{
  "detail": "Agent execution failed: Timeout exceeded"
}
```

## Agent Types

- `general`: General-purpose conversational agents
- `specialist`: Domain-specific agents with specialized knowledge
- `coordinator`: Meta-agents that coordinate other agents
- `team`: Agents representing team workspaces

## Memory Types

- `learning`: General learned information
- `pattern`: Recognized patterns in interactions
- `feedback`: User feedback and preferences
- `optimization`: Performance optimizations

## Capabilities

- `web_search`: Can perform web searches
- `code_execution`: Can execute code
- `file_access`: Can access files
- `memory_access`: Can read/write memories
- `tool_usage`: Can use external tools
- `agent_coordination`: Can coordinate other agents
- `task_breakdown`: Can break down complex tasks

## Graph Definition Schema

```typescript
interface GraphDefinition {
  nodes: Node[];
  edges: Edge[];
  entry_point: string;
  metadata?: {
    description?: string;
    version?: string;
    [key: string]: any;
  };
}

interface Node {
  id: string;
  type: "input" | "llm" | "tool" | "condition" | "memory" | "output";
  name: string;
  config?: Record<string, any>;
}

interface Edge {
  from: string;
  to: string;
  condition?: Condition;
  routes?: Record<string, string>;
}

interface Condition {
  type: "simple" | "custom";
  key?: string;
  operator?: "equals" | "not_equals" | "contains" | "greater_than" | "less_than";
  value?: any;
  name?: string;
}
```