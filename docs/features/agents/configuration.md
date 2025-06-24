# Agent System Configuration

## Environment Variables

Configure the agent system using environment variables:

```bash
# Agent execution settings
AGENT_MAX_EXECUTION_TIME=300        # Maximum execution time in seconds (default: 300)
AGENT_ENABLE_STREAMING=true         # Enable streaming responses (default: true)
AGENT_DEFAULT_TEMPERATURE=0.7       # Default LLM temperature (default: 0.7)
AGENT_MAX_TOKENS=2000              # Maximum tokens per LLM call (default: 2000)

# Rate limiting
AGENT_USER_RATE_LIMIT=100          # Executions per user per hour (default: 100)
AGENT_GLOBAL_RATE_LIMIT=10000      # Global executions per hour (default: 10000)

# Memory settings
AGENT_MEMORY_RETENTION_DAYS=90     # Days to retain agent memories (default: 90)
AGENT_MAX_MEMORIES_PER_AGENT=1000  # Maximum memories per agent (default: 1000)

# Security
AGENT_ALLOW_CUSTOM_TOOLS=false     # Allow custom tool registration (default: false)
AGENT_SANDBOX_ENABLED=true         # Enable execution sandboxing (default: true)
```

## Agent Configuration

### System Prompts

Configure default system prompts for agent types:

```python
# In src/agents/manager.py
DEFAULT_SYSTEM_PROMPTS = {
    "general": """You are a helpful AI assistant. 
    Provide clear, accurate, and helpful responses.""",
    
    "specialist": """You are a specialized AI assistant 
    with expertise in your domain. Provide detailed 
    and accurate information.""",
    
    "coordinator": """You are a coordination agent that 
    helps manage tasks and delegate to other agents.""",
    
    "team": """You are a team agent that represents 
    a collaborative workspace. Help coordinate team 
    activities."""
}
```

### Capabilities

Define available agent capabilities:

```python
AGENT_CAPABILITIES = [
    "web_search",       # Web search access
    "code_execution",   # Code execution in sandbox
    "file_access",      # File system access
    "memory_access",    # Memory read/write
    "tool_usage",       # External tool usage
    "agent_coordination", # Coordinate other agents
    "task_breakdown"    # Break down complex tasks
]
```

### Tool Configuration

Configure available tools for agents:

```python
# Tool registry configuration
TOOL_REGISTRY = {
    "web_search": {
        "class": "WebSearchTool",
        "config": {
            "api_key": "${WEB_SEARCH_API_KEY}",
            "max_results": 10
        }
    },
    "code_executor": {
        "class": "CodeExecutorTool",
        "config": {
            "sandbox": true,
            "timeout": 30,
            "languages": ["python", "javascript"]
        }
    },
    "calculator": {
        "class": "CalculatorTool",
        "config": {
            "precision": 10
        }
    }
}
```

## LLM Provider Configuration

### OpenAI Configuration

```python
# OpenAI provider settings
OPENAI_CONFIG = {
    "api_key": "${OPENAI_API_KEY}",
    "organization": "${OPENAI_ORG_ID}",
    "default_model": "gpt-4",
    "fallback_model": "gpt-3.5-turbo",
    "max_retries": 3,
    "timeout": 30
}
```

### Anthropic Configuration

```python
# Anthropic provider settings
ANTHROPIC_CONFIG = {
    "api_key": "${ANTHROPIC_API_KEY}",
    "default_model": "claude-3-opus-20240229",
    "max_retries": 3,
    "timeout": 30
}
```

### Local Model Configuration

```python
# Local model settings
LOCAL_MODEL_CONFIG = {
    "model_path": "/models/llama-2-7b",
    "device": "cuda",
    "max_memory": "8GB",
    "quantization": "int8"
}
```

## Graph Definition Limits

Configure limits for agent graph definitions:

```python
GRAPH_LIMITS = {
    "max_nodes": 50,           # Maximum nodes per graph
    "max_edges": 100,          # Maximum edges per graph
    "max_depth": 10,           # Maximum execution depth
    "max_cycles": 5,           # Maximum loop iterations
    "timeout_per_node": 60     # Timeout per node in seconds
}
```

## Memory Configuration

### Memory Types

```python
MEMORY_TYPES = {
    "learning": {
        "retention_days": 90,
        "max_entries": 1000,
        "confidence_threshold": 0.7
    },
    "pattern": {
        "retention_days": 180,
        "max_entries": 500,
        "confidence_threshold": 0.8
    },
    "feedback": {
        "retention_days": 30,
        "max_entries": 100,
        "confidence_threshold": 0.5
    },
    "optimization": {
        "retention_days": 365,
        "max_entries": 200,
        "confidence_threshold": 0.9
    }
}
```

### Memory Cleanup

```python
# Automatic memory cleanup configuration
MEMORY_CLEANUP = {
    "enabled": true,
    "schedule": "0 2 * * *",  # Daily at 2 AM
    "batch_size": 1000,
    "delete_below_confidence": 0.3,
    "archive_enabled": true,
    "archive_path": "/archives/agent_memories"
}
```

## Security Configuration

### Execution Sandbox

```python
SANDBOX_CONFIG = {
    "enabled": true,
    "container_image": "agent-sandbox:latest",
    "memory_limit": "512MB",
    "cpu_limit": "0.5",
    "network_enabled": false,
    "allowed_syscalls": ["read", "write", "open", "close"],
    "timeout": 30
}
```

### Access Control

```python
ACCESS_CONTROL = {
    "default_agent_visibility": "private",
    "allow_public_agents": true,
    "require_approval_for_tools": true,
    "admin_override": true,
    "audit_all_executions": true
}
```

## Performance Tuning

### Caching

```python
CACHE_CONFIG = {
    "enabled": true,
    "backend": "redis",
    "ttl": 3600,  # 1 hour
    "max_size": "1GB",
    "eviction_policy": "lru"
}
```

### Connection Pooling

```python
POOL_CONFIG = {
    "llm_connections": {
        "min_size": 5,
        "max_size": 20,
        "timeout": 30
    },
    "tool_connections": {
        "min_size": 2,
        "max_size": 10,
        "timeout": 15
    }
}
```

## Monitoring Configuration

### Metrics

```python
METRICS_CONFIG = {
    "enabled": true,
    "export_interval": 60,  # seconds
    "exporters": ["prometheus", "datadog"],
    "custom_metrics": [
        "agent_execution_duration",
        "token_usage_per_agent",
        "memory_operations_count",
        "tool_execution_success_rate"
    ]
}
```

### Logging

```python
AGENT_LOGGING = {
    "level": "INFO",
    "include_llm_prompts": false,  # Privacy consideration
    "include_tool_inputs": false,   # Privacy consideration
    "log_memory_operations": true,
    "structured_format": true
}
```

## Default Agent Templates

### Research Agent Template

```python
RESEARCH_AGENT_TEMPLATE = {
    "system_prompt": "You are a research specialist...",
    "temperature": 0.5,
    "capabilities": ["web_search", "memory_access"],
    "tool_ids": ["web_search", "news_search"],
    "memory_config": {
        "enable_long_term": true,
        "retention_days": 180
    }
}
```

### Coding Agent Template

```python
CODING_AGENT_TEMPLATE = {
    "system_prompt": "You are a coding specialist...",
    "temperature": 0.3,
    "capabilities": ["code_execution", "file_access"],
    "tool_ids": ["code_executor", "python_repl"],
    "sandbox_config": {
        "enabled": true,
        "languages": ["python", "javascript", "rust"]
    }
}
```

## Production Recommendations

### High Availability

```yaml
# Kubernetes deployment example
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agent-executor
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: agent-executor
        env:
        - name: AGENT_MAX_EXECUTION_TIME
          value: "300"
        - name: AGENT_ENABLE_STREAMING
          value: "true"
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
```

### Database Indexes

```sql
-- Optimize agent queries
CREATE INDEX idx_agents_tenant_active 
ON agents(tenant_id, is_active) 
WHERE is_active = true;

CREATE INDEX idx_agents_name_tenant 
ON agents(name, tenant_id);

CREATE INDEX idx_agent_memories_agent_type 
ON agent_memories(agent_id, memory_type) 
WHERE is_active = true;

-- Optimize execution tracking
CREATE INDEX idx_conversations_user_tenant 
ON conversations(user_id, tenant_id);
```

### Backup Strategy

```python
BACKUP_CONFIG = {
    "agent_definitions": {
        "enabled": true,
        "frequency": "daily",
        "retention": 30,
        "include_memories": true
    },
    "execution_logs": {
        "enabled": true,
        "frequency": "hourly",
        "retention": 7,
        "compression": true
    }
}
```