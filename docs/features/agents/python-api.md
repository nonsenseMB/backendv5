# Agent System Python API Reference

## Core Components

### AgentManager

The main interface for agent lifecycle management.

```python
from src.agents import AgentManager, AgentLoader, AgentExecutor

# Initialize components
loader = AgentLoader(llm_provider=your_llm)
executor = AgentExecutor(loader=loader)
manager = AgentManager(loader=loader, executor=executor)
```

#### Methods

##### create_agent()
```python
async def create_agent(
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
) -> Agent
```

Create a new agent with the specified configuration.

**Parameters:**
- `name`: Unique agent identifier (lowercase, alphanumeric with underscores)
- `display_name`: Human-readable name
- `agent_type`: One of: general, specialist, coordinator, team
- `graph_definition`: LangGraph flow definition
- Additional optional parameters for customization

**Returns:** Created Agent instance

##### execute_agent()
```python
async def execute_agent(
    uow: UnitOfWork,
    agent_id: UUID,
    user: User,
    conversation: Conversation,
    message: str,
    context: Optional[Dict[str, Any]] = None,
    stream: bool = True
) -> StreamingResponse
```

Execute an agent with a user message.

**Parameters:**
- `agent_id`: ID of agent to execute
- `user`: User making the request
- `conversation`: Current conversation context
- `message`: User's input message
- `context`: Additional execution context
- `stream`: Enable streaming response

**Returns:** StreamingResponse with event iterator

### AgentLoader

Handles parsing and loading of agent graph definitions.

```python
from src.agents import AgentLoader

loader = AgentLoader(
    llm_provider=your_llm,
    tools_registry={"tool_name": tool_instance}
)
```

#### Methods

##### load_agent()
```python
def load_agent(agent: Agent) -> CompiledGraph
```

Load and compile an agent's graph definition.

##### validate_agent_definition()
```python
def validate_agent_definition(
    definition: Dict[str, Any]
) -> List[str]
```

Validate a graph definition and return any errors.

### AgentExecutor

Manages agent execution with streaming support.

```python
from src.agents import AgentExecutor

executor = AgentExecutor(
    loader=agent_loader,
    max_execution_time=300,  # 5 minutes
    enable_streaming=True
)
```

#### Methods

##### execute()
```python
async def execute(
    agent: Agent,
    user: User,
    conversation: Conversation,
    message: str,
    context: Optional[Dict[str, Any]] = None,
    stream: bool = True
) -> StreamingResponse
```

Execute an agent and return streaming response.

##### cancel_execution()
```python
async def cancel_execution(execution_id: str) -> bool
```

Cancel an active execution.

### ExecutionContext

Manages state during agent execution.

```python
from src.agents import ExecutionContext

context = ExecutionContext(
    agent=agent,
    user=user,
    conversation=conversation,
    tenant_id=tenant_id,
    execution_id=execution_id
)

# Update state
context.update_state("key", "value")

# Emit events
context.emit_event(event)

# Check permissions
if context.has_permission("web_search"):
    # Perform action
```

### Event System

#### Event Types

```python
from src.agents import AgentEventType

class AgentEventType(Enum):
    AGENT_START = "agent_start"
    AGENT_COMPLETE = "agent_complete"
    AGENT_ERROR = "agent_error"
    LLM_START = "llm_start"
    LLM_TOKEN = "llm_token"
    LLM_COMPLETE = "llm_complete"
    TOOL_START = "tool_start"
    TOOL_COMPLETE = "tool_complete"
    NODE_START = "node_start"
    NODE_COMPLETE = "node_complete"
```

#### Event Classes

```python
from src.agents import AgentEvent, LLMEvent, ToolEvent

# Base event
event = AgentEvent(
    event_type=AgentEventType.AGENT_START,
    timestamp=datetime.utcnow(),
    agent_id=agent_id,
    conversation_id=conversation_id,
    user_id=user_id,
    tenant_id=tenant_id,
    metadata={}
)

# LLM event with tokens
llm_event = LLMEvent(
    event_type=AgentEventType.LLM_TOKEN,
    # ... base fields ...
    model="gpt-4",
    provider="openai",
    token="Hello"
)
```

### Node Types

#### Built-in Nodes

```python
from src.agents.nodes import (
    InputNode,
    LLMNode,
    ConditionNode,
    MemoryNode,
    OutputNode
)

# LLM node with configuration
llm_node = LLMNode(
    llm=llm_provider,
    system_prompt="You are a helpful assistant",
    config={
        "temperature": 0.7,
        "max_tokens": 500
    }
)

# Memory node for operations
memory_node = MemoryNode(
    agent_id=agent.id,
    config={
        "operation": "query",  # query, update, clear
        "memory_type": "long_term"
    }
)
```

#### Custom Nodes

```python
from src.agents.nodes import BaseNode

class CustomProcessingNode(BaseNode):
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("custom_processing", config)
    
    def invoke(self, state: Any, config: Dict[str, Any] = None) -> Any:
        # Custom processing logic
        state.context["processed"] = True
        return state
```

### Graph Definition

#### Structure

```python
graph_definition = {
    "nodes": [
        {
            "id": "input",
            "type": "input",
            "name": "User Input"
        },
        {
            "id": "process",
            "type": "llm",
            "name": "Process",
            "config": {
                "temperature": 0.7,
                "prompt_template": "Process this: {user_input}"
            }
        },
        {
            "id": "condition",
            "type": "condition",
            "name": "Check Result",
            "config": {
                "type": "simple",
                "key": "needs_clarification",
                "operator": "equals",
                "value": true
            }
        }
    ],
    "edges": [
        {"from": "START", "to": "input"},
        {"from": "input", "to": "process"},
        {
            "from": "process",
            "to": "condition",
            "condition": {
                "type": "simple",
                "key": "needs_clarification",
                "operator": "equals",
                "value": true
            },
            "routes": {
                "true": "clarify",
                "false": "output"
            }
        }
    ],
    "entry_point": "input"
}
```

### Memory Management

```python
# Add memory to agent
memory = await manager.add_agent_memory(
    uow=uow,
    agent_id=agent.id,
    memory_type="learning",  # learning, pattern, feedback, optimization
    content="User prefers detailed explanations",
    user_id=user.id,
    confidence=0.8,
    source="user_feedback"  # user_feedback, self_learning, system
)

# Query memories
memories = await manager.get_agent_memories(
    uow=uow,
    agent_id=agent.id,
    memory_type="learning",
    user_id=user.id,
    limit=10
)
```

### Default Agents

```python
from src.agents.defaults import (
    get_research_agent_definition,
    get_coding_agent_definition,
    get_coordinator_agent_definition,
    DEFAULT_AGENT_CONFIGS
)

# Get default definitions
research_def = get_research_agent_definition()
coding_def = get_coding_agent_definition()

# Create default agents for tenant
agents = await manager.create_default_agents(
    uow=uow,
    tenant_id=tenant_id,
    created_by=admin_user_id
)
```

## Exception Handling

```python
from src.agents.exceptions import (
    AgentNotFoundError,
    AgentExecutionError,
    RateLimitExceededError,
    ValidationError
)

try:
    agent = await manager.execute_agent(...)
except AgentNotFoundError:
    # Handle missing agent
except RateLimitExceededError as e:
    # Handle rate limit
    retry_after = e.details.get("retry_after")
except AgentExecutionError as e:
    # Handle execution failure
    execution_id = e.details.get("execution_id")
```

## Integration Examples

### Creating a Custom Agent

```python
# Define custom graph
custom_graph = {
    "nodes": [
        {"id": "input", "type": "input", "name": "Input"},
        {"id": "analyze", "type": "llm", "name": "Analyze"},
        {"id": "search", "type": "tool", "name": "Search", 
         "config": {"tool_ids": ["web_search"]}},
        {"id": "synthesize", "type": "llm", "name": "Synthesize"},
        {"id": "output", "type": "output", "name": "Output"}
    ],
    "edges": [
        {"from": "START", "to": "input"},
        {"from": "input", "to": "analyze"},
        {"from": "analyze", "to": "search"},
        {"from": "search", "to": "synthesize"},
        {"from": "synthesize", "to": "output"},
        {"from": "output", "to": "END"}
    ],
    "entry_point": "input"
}

# Create agent
agent = await manager.create_agent(
    uow=uow,
    name="custom_research_agent",
    display_name="Custom Research Agent",
    agent_type="specialist",
    specialization="research",
    graph_definition=custom_graph,
    system_prompt="You are a research specialist...",
    capabilities=["web_search", "synthesis"],
    created_by=user.id,
    tenant_id=tenant.id
)
```

### Streaming Execution

```python
# Execute with streaming
response = await manager.execute_agent(
    uow=uow,
    agent_id=agent.id,
    user=user,
    conversation=conversation,
    message="Research quantum computing breakthroughs",
    stream=True
)

# Process events
async for event in response.events:
    if event.event_type == AgentEventType.LLM_TOKEN:
        # Stream token to user
        print(event.metadata.get("token"), end="")
    elif event.event_type == AgentEventType.TOOL_START:
        print(f"\nUsing tool: {event.metadata.get('tool_name')}")
    elif event.event_type == AgentEventType.AGENT_COMPLETE:
        print(f"\nCompleted: {event.metadata.get('final_output')}")
```

### Memory-Enhanced Agent

```python
# Create agent with memory access
agent = await manager.create_agent(
    uow=uow,
    name="memory_agent",
    display_name="Memory-Enhanced Assistant",
    agent_type="general",
    graph_definition=memory_enhanced_graph,
    capabilities=["memory_access"],
    created_by=user.id,
    tenant_id=tenant.id
)

# Add learning from interaction
await manager.add_agent_memory(
    uow=uow,
    agent_id=agent.id,
    memory_type="pattern",
    content="User asks about AI news every Monday",
    user_id=user.id,
    confidence=0.9,
    source="self_learning"
)
```