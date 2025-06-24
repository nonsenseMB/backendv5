# Agent System Documentation

The nAI Backend v5 Agent System provides a powerful, LangGraph-based framework for creating and managing AI agents with dynamic graph execution, streaming responses, and comprehensive access control.

## Overview

The agent system enables:
- **Dynamic Agent Creation**: Define agents using JSON graph definitions
- **Flexible Execution**: Support for streaming and non-streaming responses
- **Access Control**: Multi-tenant isolation with role-based permissions
- **Memory Management**: Short-term and long-term memory for agents
- **Tool Integration**: Connect agents to external tools and services
- **Event Streaming**: Real-time event streaming during execution

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   API Layer     │────▶│  Agent Manager  │────▶│ Agent Executor  │
│  (FastAPI)      │     │ (Access Control)│     │  (Streaming)    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                │                         │
                                ▼                         ▼
                        ┌─────────────────┐     ┌─────────────────┐
                        │  Agent Loader   │     │ Execution Context│
                        │ (Graph Parser)  │     │   (State Mgmt)  │
                        └─────────────────┘     └─────────────────┘
```

## Quick Start

### 1. Create an Agent

```python
POST /api/v1/agents
{
  "name": "research_assistant",
  "display_name": "Research Assistant",
  "agent_type": "specialist",
  "specialization": "research",
  "graph_definition": {
    "nodes": [
      {
        "id": "input",
        "type": "input",
        "name": "User Query"
      },
      {
        "id": "llm",
        "type": "llm",
        "name": "Process Query",
        "config": {
          "temperature": 0.7
        }
      },
      {
        "id": "output",
        "type": "output",
        "name": "Final Response"
      }
    ],
    "edges": [
      {"from": "START", "to": "input"},
      {"from": "input", "to": "llm"},
      {"from": "llm", "to": "output"},
      {"from": "output", "to": "END"}
    ],
    "entry_point": "input"
  }
}
```

### 2. Execute the Agent

```python
POST /api/v1/agents/{agent_id}/execute
{
  "message": "What are the latest developments in AI?",
  "stream": true
}
```

### 3. Stream Events

```javascript
const eventSource = new EventSource(`/api/v1/agents/${agentId}/execute`);

eventSource.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(`Event: ${data.event_type}`, data);
};
```

## Graph Definition Structure

### Nodes

Agents are built using nodes that represent different operations:

- **input**: Entry point for user messages
- **llm**: Language model processing
- **tool**: External tool execution
- **condition**: Conditional branching
- **memory**: Memory operations
- **output**: Final response formatting

### Edges

Edges define the flow between nodes:

```json
{
  "from": "node_id",
  "to": "node_id",
  "condition": {  // Optional
    "type": "simple",
    "key": "has_results",
    "operator": "equals",
    "value": true
  }
}
```

## Agent Types

### 1. General Agents
Basic conversational agents for Q&A and general assistance.

### 2. Specialist Agents
Domain-specific agents with specialized knowledge:
- Research specialists
- Coding specialists
- Analysis specialists

### 3. Coordinator Agents
Meta-agents that coordinate other agents for complex tasks.

### 4. Team Agents
Agents representing collaborative team workspaces.

## Memory System

### Short-term Memory
- Conversation context
- Recent interactions
- Temporary state

### Long-term Memory
- Learned patterns
- User preferences
- Historical context

```python
POST /api/v1/agents/{agent_id}/memories
{
  "memory_type": "learning",
  "content": "User prefers concise responses",
  "confidence": 0.9,
  "source": "user_feedback"
}
```

## Access Control

### Public Agents
- Accessible to all users in the tenant
- Suitable for general-purpose assistants

### Private Agents
- Restricted to creator and authorized users
- Role-based access control

### Team Agents
- Shared within team boundaries
- Collaborative features

## Event Types

During execution, agents emit various events:

- **agent_start**: Execution begins
- **agent_complete**: Execution completes
- **agent_error**: Error occurred
- **llm_start**: LLM processing starts
- **llm_token**: Streaming token
- **llm_complete**: LLM processing complete
- **tool_start**: Tool execution starts
- **tool_complete**: Tool execution complete
- **node_start**: Node execution starts
- **node_complete**: Node execution complete

## Default Agents

The system includes pre-configured agents:

### Research Agent
- Web search capabilities
- Information synthesis
- Source citation

### Coding Agent
- Code generation
- Debugging assistance
- Code review

### Coordinator Agent
- Task breakdown
- Multi-agent coordination
- Result synthesis

## Best Practices

### 1. Graph Design
- Keep graphs simple and focused
- Use meaningful node names
- Implement proper error handling

### 2. Performance
- Use streaming for long-running tasks
- Implement rate limiting
- Monitor execution times

### 3. Security
- Validate all inputs
- Use least-privilege access
- Audit agent actions

### 4. Memory Management
- Clean up old memories periodically
- Use appropriate confidence scores
- Respect user privacy

## Troubleshooting

### Common Issues

1. **Graph Validation Errors**
   - Ensure all node types are valid
   - Check edge references exist
   - Verify entry point is defined

2. **Execution Timeouts**
   - Reduce graph complexity
   - Optimize tool usage
   - Increase timeout limits

3. **Access Denied**
   - Verify user permissions
   - Check agent visibility settings
   - Ensure tenant isolation

## Advanced Features

### Custom Nodes
Create custom node types for specialized operations.

### Tool Integration
Connect agents to MCP servers and external APIs.

### Multi-Agent Coordination
Build complex workflows with multiple agents.

### Export/Import
Export agent configurations for backup or sharing.

## API Reference

See the [Python API Reference](python-api.md) for detailed API documentation.