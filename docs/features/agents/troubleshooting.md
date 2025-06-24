# Agent System Troubleshooting Guide

## Common Issues and Solutions

### 1. Graph Validation Errors

#### Issue: "Graph definition missing required field"
```
ValidationError: Graph definition missing required field: nodes
```

**Solution:**
Ensure your graph definition includes all required fields:
```python
{
    "nodes": [...],      # Required
    "edges": [...],      # Required  
    "entry_point": "..." # Required
}
```

#### Issue: "Unknown node type"
```
ValidationError: Unknown node type: custom_node
```

**Solution:**
Use only supported node types:
- `input`
- `llm`
- `tool`
- `condition`
- `memory`
- `output`

Or register custom nodes:
```python
loader.node_types["custom_node"] = CustomNodeClass
```

#### Issue: "Graph contains cycles"
```
ValidationError: Graph contains cycles: [['a', 'b', 'c', 'a']]
```

**Solution:**
Remove circular dependencies or use proper conditional routing:
```python
{
    "from": "node_a",
    "to": "node_b",
    "condition": {
        "type": "simple",
        "key": "should_continue",
        "operator": "equals",
        "value": true
    }
}
```

### 2. Execution Errors

#### Issue: "Agent execution timed out"
```
AgentExecutionError: Agent execution timed out after 300 seconds
```

**Solutions:**
1. Increase timeout:
```python
executor = AgentExecutor(
    loader=loader,
    max_execution_time=600  # 10 minutes
)
```

2. Optimize graph:
- Reduce node count
- Simplify LLM prompts
- Cache intermediate results

#### Issue: "Rate limit exceeded"
```
RateLimitExceededError: User rate limit exceeded
```

**Solutions:**
1. Wait for rate limit reset:
```python
try:
    response = await executor.execute(...)
except RateLimitExceededError as e:
    retry_after = e.details.get("retry_after", 3600)
    await asyncio.sleep(retry_after)
```

2. Request rate limit increase for user/tenant

#### Issue: "Insufficient permissions"
```
InsufficientPermissionsError: User does not have permission to execute agent
```

**Solutions:**
1. Make agent public:
```python
await manager.update_agent(
    agent_id=agent.id,
    is_public=True
)
```

2. Grant user appropriate role:
```python
agent.allowed_roles = ["member", "viewer"]
```

### 3. Memory Issues

#### Issue: "Memory limit exceeded"
```
ValidationError: Agent memory limit exceeded (1000 memories)
```

**Solutions:**
1. Clean up old memories:
```python
# Delete memories older than 30 days
cutoff_date = datetime.utcnow() - timedelta(days=30)
await uow.session.execute(
    delete(AgentMemory).where(
        AgentMemory.created_at < cutoff_date
    )
)
```

2. Increase memory limit in configuration

#### Issue: "Memory query returns no results"
**Solutions:**
1. Check memory type:
```python
memories = await manager.get_agent_memories(
    agent_id=agent.id,
    memory_type="learning"  # Correct type
)
```

2. Verify memories are active:
```python
memories = await uow.session.execute(
    select(AgentMemory).where(
        AgentMemory.agent_id == agent_id,
        AgentMemory.is_active == True
    )
)
```

### 4. Streaming Issues

#### Issue: "No events received from stream"
**Solutions:**
1. Ensure streaming is enabled:
```python
response = await executor.execute(
    stream=True  # Must be True
)
```

2. Check event listener setup:
```python
async for event in response.events:
    print(f"Event: {event.event_type}")
```

#### Issue: "Events arrive out of order"
**Solution:**
Use event timestamps for ordering:
```python
events = []
async for event in response.events:
    events.append(event)

# Sort by timestamp
events.sort(key=lambda e: e.timestamp)
```

### 5. Tool Integration Issues

#### Issue: "Tool not found in registry"
```
Warning: Tool not found in registry: web_search
```

**Solution:**
Register tools before use:
```python
from langchain.tools import WebSearchTool

loader = AgentLoader(
    llm_provider=llm,
    tools_registry={
        "web_search": WebSearchTool()
    }
)
```

#### Issue: "Tool execution failed"
**Solutions:**
1. Check tool configuration:
```python
tool_config = {
    "timeout": 30,
    "retry_count": 3,
    "api_key": os.getenv("TOOL_API_KEY")
}
```

2. Verify tool permissions:
```python
agent.capabilities = ["tool_usage", "web_search"]
agent.tool_ids = [tool.id]
```

### 6. Performance Issues

#### Issue: "Slow agent responses"
**Solutions:**
1. Enable caching:
```python
from functools import lru_cache

@lru_cache(maxsize=100)
async def get_cached_response(prompt: str):
    return await llm.agenerate([prompt])
```

2. Use smaller models for simple tasks:
```python
agent.model_preferences = {
    "simple_tasks": "gpt-3.5-turbo",
    "complex_tasks": "gpt-4"
}
```

3. Implement node-level timeouts:
```python
node_config = {
    "timeout": 10,  # 10 seconds per node
    "skip_on_timeout": True
}
```

### 7. Database Issues

#### Issue: "Agent not found"
```
AgentNotFoundError: Agent 00000000-0000-0000-0000-000000000001 not found
```

**Solutions:**
1. Verify agent exists:
```python
agent = await uow.agents.get(agent_id)
if not agent:
    print("Agent does not exist")
```

2. Check tenant isolation:
```python
# Ensure correct tenant context
agent = await uow.agents.get_by_name_and_tenant(
    name="my_agent",
    tenant_id=user.tenant_id
)
```

### 8. Event Processing Issues

#### Issue: "Missing event data"
**Solution:**
Check event metadata:
```python
async for event in response.events:
    if event.event_type == AgentEventType.LLM_TOKEN:
        token = event.metadata.get("token", "")
        if not token:
            logger.warning("Empty token received")
```

#### Issue: "Event stream disconnects"
**Solutions:**
1. Implement reconnection:
```python
max_retries = 3
for attempt in range(max_retries):
    try:
        async for event in response.events:
            process_event(event)
        break
    except ConnectionError:
        if attempt < max_retries - 1:
            await asyncio.sleep(2 ** attempt)
```

2. Use heartbeat events:
```python
last_event_time = time.time()
timeout = 30  # seconds

async for event in response.events:
    last_event_time = time.time()
    process_event(event)
    
    # Check for timeout
    if time.time() - last_event_time > timeout:
        raise TimeoutError("Event stream timeout")
```

## Debugging Techniques

### 1. Enable Debug Logging

```python
import logging
logging.getLogger("src.agents").setLevel(logging.DEBUG)
```

### 2. Trace Execution Path

```python
class DebugExecutor(AgentExecutor):
    async def _run_graph_async(self, graph, state, context):
        logger.debug(f"Executing graph: {graph}")
        logger.debug(f"Initial state: {state.to_dict()}")
        
        result = await super()._run_graph_async(graph, state, context)
        
        logger.debug(f"Final state: {result.to_dict()}")
        logger.debug(f"Execution path: {result.execution_path}")
        
        return result
```

### 3. Monitor Resource Usage

```python
import psutil
import asyncio

async def monitor_execution(executor, agent, user, conversation, message):
    process = psutil.Process()
    
    start_memory = process.memory_info().rss / 1024 / 1024  # MB
    start_time = time.time()
    
    response = await executor.execute(agent, user, conversation, message)
    
    end_memory = process.memory_info().rss / 1024 / 1024  # MB
    duration = time.time() - start_time
    
    print(f"Execution time: {duration:.2f}s")
    print(f"Memory usage: {end_memory - start_memory:.2f}MB")
    
    return response
```

### 4. Validate Graph Before Execution

```python
def validate_graph_thoroughly(definition):
    errors = []
    
    # Check for unreachable nodes
    reachable = set()
    entry = definition["entry_point"]
    
    def traverse(node_id):
        if node_id in reachable:
            return
        reachable.add(node_id)
        
        for edge in definition["edges"]:
            if edge["from"] == node_id:
                traverse(edge["to"])
    
    traverse(entry)
    
    all_nodes = {node["id"] for node in definition["nodes"]}
    unreachable = all_nodes - reachable
    
    if unreachable:
        errors.append(f"Unreachable nodes: {unreachable}")
    
    return errors
```

## Error Recovery Strategies

### 1. Graceful Degradation

```python
async def execute_with_fallback(manager, agent_id, user, conversation, message):
    try:
        # Try primary agent
        return await manager.execute_agent(
            agent_id=agent_id,
            user=user,
            conversation=conversation,
            message=message
        )
    except AgentExecutionError:
        # Fall back to simpler agent
        fallback_agent = await manager.get_agent(
            agent_id=FALLBACK_AGENT_ID,
            user_id=user.id
        )
        return await manager.execute_agent(
            agent_id=fallback_agent.id,
            user=user,
            conversation=conversation,
            message=message
        )
```

### 2. Checkpoint Recovery

```python
class CheckpointedExecution:
    def __init__(self, executor):
        self.executor = executor
        self.checkpoints = {}
    
    async def execute_with_checkpoints(self, agent, user, conversation, message):
        execution_id = str(uuid.uuid4())
        
        try:
            response = await self.executor.execute(
                agent, user, conversation, message
            )
            
            # Save successful execution
            self.checkpoints[execution_id] = {
                "agent_id": agent.id,
                "message": message,
                "response": response.final_output
            }
            
            return response
            
        except Exception as e:
            # Attempt recovery from checkpoint
            if execution_id in self.checkpoints:
                checkpoint = self.checkpoints[execution_id]
                logger.info(f"Recovering from checkpoint: {execution_id}")
                # Return cached response
                return checkpoint["response"]
            raise
```

## Getting Help

### 1. Check Logs

```bash
# Agent execution logs
grep "agent_id" /var/log/app/agent.log

# Error logs
grep "ERROR" /var/log/app/agent.log | tail -50
```

### 2. Enable Verbose Output

```python
# Set in environment
export AGENT_DEBUG=true
export AGENT_LOG_LEVEL=DEBUG
```

### 3. Report Issues

When reporting issues, include:
- Agent ID and configuration
- Graph definition
- Error message and stack trace
- Execution context (user, tenant, conversation)
- Recent changes or deployments