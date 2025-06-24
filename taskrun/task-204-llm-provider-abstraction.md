# Task 204: LLM Provider Abstraction Layer

## Task Overview
**Sprint**: 200  
**Priority**: High  
**Effort**: 5 days  
**Dependencies**: 
- Agent system (Task 201) needs LLM providers
- Secure key storage infrastructure

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
- `/docs/database/DATABASE_MODELS_V5_COMPLETE.md` - Check for provider tables
- `/CLAUDE.md` - Security requirements
- `/docs/CONCEPT_SUMMARY.md` - Multi-LLM vision

## Task Description
Create a provider-agnostic abstraction layer for LLM interactions. This allows agents to use different LLM providers (OpenAI, Anthropic, Google, Azure, Ollama) transparently with secure API key management.

## Database Schema

### 1. Check/Create Provider Tables:
```sql
-- LLM provider configurations per tenant
CREATE TABLE llm_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    provider_type VARCHAR(50) NOT NULL, -- openai, anthropic, google, azure, ollama
    encrypted_api_key TEXT NOT NULL,
    config JSONB DEFAULT '{}', -- Provider-specific config
    is_active BOOLEAN DEFAULT true,
    is_default BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    -- Constraints
    UNIQUE(tenant_id, provider_type),
    INDEX idx_llm_providers_tenant (tenant_id),
    INDEX idx_llm_providers_active (tenant_id, is_active)
);

-- Provider usage tracking
CREATE TABLE llm_provider_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID NOT NULL REFERENCES llm_providers(id),
    date DATE NOT NULL,
    model VARCHAR(100) NOT NULL,
    prompt_tokens INTEGER DEFAULT 0,
    completion_tokens INTEGER DEFAULT 0,
    total_cost DECIMAL(10,6) DEFAULT 0,
    request_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    
    -- Constraints
    UNIQUE(provider_id, date, model),
    INDEX idx_provider_usage_date (provider_id, date)
);
```

## Implementation Components

### 1. Base Provider Interface
```python
# src/llm/base.py
```

Abstract interface all providers must implement:
- `complete()` - Synchronous completion
- `stream_completion()` - Streaming responses
- `count_tokens()` - Token counting
- `check_health()` - Provider health check
- `get_supported_models()` - Available models
- `estimate_cost()` - Cost calculation

### 2. Provider Implementations

#### OpenAI Provider
```python
# src/llm/providers/openai_provider.py
```

Features:
- Support GPT-4, GPT-3.5 models
- Streaming with token counting
- Function calling support
- Embeddings (future)

#### Anthropic Provider
```python
# src/llm/providers/anthropic_provider.py
```

Features:
- Claude 3 models
- Streaming support
- System prompts
- Token counting with anthropic library

#### Google Provider
```python
# src/llm/providers/google_provider.py
```

Features:
- Gemini Pro models
- Streaming support
- Multi-modal (future)

#### Azure OpenAI Provider
```python
# src/llm/providers/azure_provider.py
```

Features:
- Deployment-based routing
- Azure-specific auth
- Regional endpoints

#### Ollama Provider
```python
# src/llm/providers/ollama_provider.py
```

Features:
- Local model support
- Custom model loading
- No API key required

### 3. Provider Manager
```python
# src/llm/manager.py
```

Central manager for all providers:
- Provider registration
- Secure key storage/retrieval
- Provider instance caching
- Model → Provider routing
- Usage tracking

Key methods:
- `add_provider()` - Register new provider
- `get_provider()` - Get provider for model
- `update_provider()` - Update configuration
- `remove_provider()` - Deactivate provider
- `test_provider()` - Health check

### 4. Security Layer
```python
# src/llm/security.py
```

API key encryption:
- AES-256 encryption
- Fernet symmetric encryption
- Key rotation support
- Audit logging

### 5. Cost Tracking
```python
# src/llm/cost_tracker.py
```

Track usage and costs:
- Per-request tracking
- Daily aggregation
- Cost alerts
- Usage reports

### 6. Model Configuration
```python
# src/llm/models.py
```

Model metadata:
```python
MODEL_INFO = {
    "gpt-4": {
        "provider": "openai",
        "context_window": 8192,
        "cost_per_1k_prompt": 0.03,
        "cost_per_1k_completion": 0.06,
    },
    "claude-3-opus": {
        "provider": "anthropic",
        "context_window": 200000,
        "cost_per_1k_prompt": 0.015,
        "cost_per_1k_completion": 0.075,
    },
    # ... more models
}
```

## API Endpoints

### Provider Management API
```python
# src/api/v1/llm_providers/router.py
```

Endpoints:
```
POST   /api/v1/llm-providers              # Add provider
GET    /api/v1/llm-providers              # List providers
GET    /api/v1/llm-providers/{id}         # Get provider
PUT    /api/v1/llm-providers/{id}         # Update provider
DELETE /api/v1/llm-providers/{id}         # Remove provider
POST   /api/v1/llm-providers/{id}/test    # Test provider
GET    /api/v1/llm-providers/{id}/usage   # Get usage stats
```

### Schemas
```python
# src/api/v1/llm_providers/schemas.py
```

Request/Response schemas:
- `AddProviderRequest`
- `UpdateProviderRequest`
- `ProviderResponse`
- `ProviderUsageResponse`
- `TestProviderRequest`

## Integration with Agents

### 1. Agent Node Integration
Agents access LLMs through the provider manager:
```python
# In LLM node execution
provider = llm_router.get_provider(tenant_id, model)
response = await provider.stream_completion(...)
```

### 2. Context Passing
Execution context includes:
- `llm_router` - Provider manager instance
- `tenant_id` - For provider lookup
- Model preferences

### 3. Error Handling
Handle provider-specific errors:
- Rate limiting
- Token limits
- Network errors
- Invalid API keys

## Testing Requirements

### Unit Tests:
- Each provider implementation
- Encryption/decryption
- Cost calculations
- Model routing

### Integration Tests:
- Provider registration flow
- Multi-provider setup
- Provider switching
- Error scenarios

### Mock Provider
Create mock provider for testing:
```python
# src/llm/providers/mock_provider.py
```

## Performance Optimizations

### 1. Provider Caching
- Cache provider instances
- Connection pooling
- Lazy initialization

### 2. Request Batching
- Batch small requests
- Optimize token usage
- Reduce API calls

### 3. Fallback Strategy
- Primary/secondary providers
- Automatic failover
- Load balancing

## Monitoring

### Metrics to Track:
- Request latency by provider
- Error rates
- Token usage
- Cost per tenant
- Model popularity

### Alerts:
- High error rates
- Cost threshold exceeded
- Provider unavailable
- Slow response times

## Success Criteria

- [ ] All 5 provider types implemented
- [ ] Streaming working for all providers
- [ ] API keys securely encrypted
- [ ] Cost tracking accurate
- [ ] Provider switching seamless
- [ ] Error handling robust
- [ ] Tests covering all providers
- [ ] Performance benchmarks met

## Migration Strategy

For existing systems:
1. Migrate existing API keys
2. Create provider records
3. Update agent configurations
4. Test with subset of traffic
5. Full rollout

## Environment Configuration

```bash
# Encryption key
LLM_ENCRYPTION_KEY=base64_encoded_32_byte_key

# Provider defaults
DEFAULT_OPENAI_MODEL=gpt-4
DEFAULT_ANTHROPIC_MODEL=claude-3-sonnet
DEFAULT_GOOGLE_MODEL=gemini-pro

# Rate limits
LLM_RATE_LIMIT_PER_MINUTE=60
LLM_RATE_LIMIT_PER_DAY=10000

# Cost alerts
LLM_DAILY_COST_ALERT_THRESHOLD=100.00
```

## Future Enhancements

Consider for later:
1. Model fine-tuning support
2. Prompt caching
3. Response caching
4. A/B testing framework
5. Custom model support