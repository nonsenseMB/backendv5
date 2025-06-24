# Task 205: Short-Term Memory (STM) System

## Task Overview
**Sprint**: 200  
**Priority**: Medium  
**Effort**: 3 days  
**Dependencies**: 
- Redis infrastructure available
- Conversation system (Task 202) complete

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
- `/docs/CONCEPT_SUMMARY.md` - Memory system overview
- `/docs/architecture/PLATFORM_ARCHITECTURE.md` - Memory architecture
- Redis documentation for data structures

## Task Description
Implement the Short-Term Memory (STM) system with a 4-hour TTL for active conversation context. STM stores temporary context that enhances conversation quality without permanent storage.

## Architecture Overview

```
Conversation → Extract Context → Store in Redis (4h TTL) → Query for Agent
                     ↓
                LLM Analysis
```

## Redis Schema Design

### 1. STM Entry Structure
```
Key: stm:{conversation_id}
Type: Sorted Set
Score: Importance (0.0 - 1.0)
Value: JSON encoded context entry
TTL: 4 hours (14400 seconds)
```

### 2. Context Entry Format
```json
{
  "id": "uuid",
  "type": "preference|fact|goal|constraint",
  "content": "User prefers Python",
  "importance": 0.9,
  "timestamp": "2024-01-20T10:00:00Z",
  "source": "message|extraction|explicit",
  "metadata": {
    "message_id": "uuid",
    "confidence": 0.95
  }
}
```

### 3. User Preference Cache
```
Key: stm:user:{user_id}:preferences
Type: Hash
Fields: preference_type → value
TTL: No expiry (persistent preferences)
```

## Implementation Components

### 1. STM Core Service
```python
# src/memory/short_term.py
```

Core methods:
- `store_context()` - Add context with importance
- `get_context()` - Retrieve relevant context
- `extract_from_conversation()` - LLM-based extraction
- `clear_conversation()` - Remove STM for conversation
- `update_importance()` - Adjust context importance
- `get_top_contexts()` - Get most important contexts

Key features:
- Automatic TTL management
- Importance-based ranking
- Size limits (top 20 entries)
- Deduplication logic

### 2. Context Extractor
```python
# src/memory/extractors/context_extractor.py
```

Extract different context types:
- **Preferences**: "Call me X", "I prefer Y"
- **Facts**: Stated information about user/project
- **Goals**: What user wants to achieve
- **Constraints**: Limitations or requirements
- **Entities**: People, projects, technologies mentioned

Extraction methods:
- Pattern-based extraction (fast)
- LLM-based extraction (accurate)
- Hybrid approach

### 3. STM Middleware
```python
# src/memory/middleware.py
```

Integrate with message flow:
- Process each message for context
- Periodic batch extraction
- Update importance based on usage
- Clean up old entries

### 4. Memory Integration Service
```python
# src/memory/integration.py
```

Coordinate memory systems:
- STM → LTM promotion
- Context aggregation
- Memory search across systems
- Deduplication

## Integration Points

### 1. Message Service Integration
Update message processing:
```python
# After user message
await stm_middleware.process_message(conversation_id, message)

# Before agent execution
stm_context = await stm.get_context(conversation_id)
agent_input["stm_context"] = stm_context
```

### 2. Agent Integration
Agents receive STM context:
```python
{
  "stm_context": {
    "preferences": [...],
    "facts": [...],
    "goals": [...],
    "recent_entities": [...]
  }
}
```

### 3. Checkpoint Integration
When creating checkpoints:
- Extract key contexts from STM
- Include in checkpoint summary
- Promote important items to LTM

## Context Extraction Patterns

### 1. Preference Patterns
```python
PREFERENCE_PATTERNS = [
    r"call me (\w+)",
    r"I prefer (\w+)",
    r"I like (\w+)",
    r"always use (\w+)",
    r"please (\w+)",
]
```

### 2. Fact Patterns
```python
FACT_PATTERNS = [
    r"I am (?:a|an) (\w+)",
    r"I work (?:at|for) (\w+)",
    r"my (\w+) is (\w+)",
    r"I have (\w+)",
]
```

### 3. LLM Extraction Prompt
```python
EXTRACTION_PROMPT = """
Analyze this conversation segment and extract:
1. User preferences (how they want to be addressed, style preferences)
2. Important facts (about user, their work, projects)
3. Goals or objectives mentioned
4. Technical requirements or constraints

Format as JSON array with type, content, and importance (0-1).
"""
```

## API Endpoints

### Memory API
```python
# src/api/v1/memory/router.py
```

Endpoints:
```
GET    /api/v1/conversations/{id}/stm      # Get STM for conversation
POST   /api/v1/conversations/{id}/stm      # Add manual context
DELETE /api/v1/conversations/{id}/stm/{id} # Remove context
POST   /api/v1/memory/extract              # Manual extraction
```

## Performance Optimizations

### 1. Redis Optimization
- Use pipelining for batch operations
- Implement connection pooling
- Monitor memory usage
- Set appropriate max memory policy

### 2. Extraction Optimization
- Cache extraction results
- Batch messages for extraction
- Use async extraction
- Implement circuit breaker

### 3. Query Optimization
- Index by importance
- Limit context size
- Implement pagination
- Cache frequent queries

## Monitoring & Metrics

### Metrics to Track:
- STM hit rate
- Average context count
- Extraction latency
- Memory usage
- TTL expirations

### Logging:
- Context additions
- Extraction events
- Query patterns
- Performance metrics

## Testing Implementation

### Unit Tests:
- Context storage/retrieval
- TTL behavior
- Importance ranking
- Extraction patterns

### Integration Tests:
- Message flow integration
- Agent context delivery
- Memory promotion
- Performance under load

### Test Scenarios:
1. Multi-turn conversation
2. Preference changes
3. Context overflow
4. TTL expiration
5. Concurrent access

## Configuration

### Environment Variables:
```bash
# Redis configuration
STM_REDIS_URL=redis://localhost:6379/1
STM_REDIS_MAX_CONNECTIONS=50

# STM settings
STM_TTL_HOURS=4
STM_MAX_CONTEXTS_PER_CONVERSATION=20
STM_IMPORTANCE_THRESHOLD=0.7
STM_EXTRACTION_INTERVAL=5  # messages

# Extraction settings
STM_EXTRACTION_MODEL=gpt-3.5-turbo
STM_EXTRACTION_BATCH_SIZE=10
STM_PATTERN_MATCHING_ENABLED=true
```

## Success Criteria

- [ ] Context stored with proper TTL
- [ ] Importance-based ranking working
- [ ] Pattern extraction functional
- [ ] LLM extraction accurate
- [ ] Integration with messages smooth
- [ ] Performance targets met
- [ ] Memory limits enforced
- [ ] Tests passing >80% coverage

## Error Handling

Handle these scenarios:
- Redis connection failure
- Extraction timeout
- Invalid context format
- Memory limit exceeded
- TTL expiration during use

## Future Enhancements

Consider for later:
1. Context clustering
2. Cross-conversation patterns
3. Team-shared contexts
4. Context versioning
5. ML-based importance scoring

## Migration Notes

For existing conversations:
- No migration needed (greenfield)
- STM builds up naturally
- Consider bulk extraction for active conversations

## Security Considerations

1. **Data Privacy**:
   - STM contains sensitive info
   - Encrypt at rest in Redis
   - Audit access logs

2. **Tenant Isolation**:
   - Prefix keys with tenant ID
   - No cross-tenant access
   - Regular security audits

3. **PII Handling**:
   - Detect and mask PII
   - Compliance with GDPR
   - Right to erasure support