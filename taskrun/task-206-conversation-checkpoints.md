# Task 206: Conversation Checkpoints System

## Task Overview
**Sprint**: 200  
**Priority**: Medium  
**Effort**: 2 days  
**Dependencies**: 
- Conversation system (Task 202) complete
- STM system (Task 205) complete
- Message tracking in place

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
- `/docs/database/DATABASE_MODELS_V5_COMPLETE.md` - Check checkpoint tables
- User requirement: "Checkpoints with summaries every X messages"

## Task Description
Implement automatic checkpoint creation for conversations every 50 messages. Checkpoints include summaries, key points, and entity extraction to enable efficient context retrieval for long conversations.

## Database Schema

### 1. Verify/Create Checkpoint Table:
```sql
-- Conversation checkpoints for summarization
CREATE TABLE conversation_checkpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    checkpoint_number INTEGER NOT NULL, -- Sequential number
    message_count INTEGER NOT NULL, -- Messages in this checkpoint
    start_message_id UUID NOT NULL REFERENCES messages(id),
    end_message_id UUID NOT NULL REFERENCES messages(id),
    
    -- Checkpoint content
    summary TEXT NOT NULL,
    key_points JSONB DEFAULT '[]', -- Array of key points
    entities JSONB DEFAULT '[]', -- Extracted entities
    topics JSONB DEFAULT '[]', -- Main topics discussed
    
    -- Metadata
    token_count INTEGER NOT NULL,
    processing_time_ms INTEGER,
    created_at TIMESTAMP DEFAULT NOW(),
    
    -- Indexes
    INDEX idx_checkpoints_conversation (conversation_id),
    INDEX idx_checkpoints_created (created_at),
    UNIQUE(conversation_id, checkpoint_number)
);
```

## Implementation Components

### 1. Checkpoint Service
```python
# src/services/checkpoint_service.py
```

Core methods:
- `create_checkpoint()` - Generate checkpoint for conversation
- `should_create_checkpoint()` - Check if checkpoint needed
- `get_checkpoints()` - List checkpoints for conversation
- `get_checkpoint_context()` - Build context from checkpoints
- `delete_old_checkpoints()` - Cleanup old checkpoints

Checkpoint creation flow:
1. Check message count since last checkpoint
2. Retrieve messages for summarization
3. Generate summary using LLM
4. Extract key points and entities
5. Store checkpoint
6. Update conversation metadata

### 2. Summary Generator
```python
# src/services/checkpoint/summary_generator.py
```

Generate comprehensive summaries:
- Conversation summary (what was discussed)
- Key decisions/outcomes
- Important facts mentioned
- Action items identified
- Technical details covered

LLM prompt template:
```python
CHECKPOINT_PROMPT = """
Summarize this conversation segment:

{messages}

Provide:
1. Brief summary (2-3 sentences)
2. Key points (bullet list)
3. Entities mentioned (people, projects, technologies)
4. Main topics discussed
5. Any decisions or action items

Format as JSON.
"""
```

### 3. Entity Extractor
```python
# src/services/checkpoint/entity_extractor.py
```

Extract and categorize entities:
- People (names, roles)
- Organizations
- Projects
- Technologies
- Dates/Deadlines
- URLs/Resources

### 4. Checkpoint Scheduler
```python
# src/services/checkpoint/scheduler.py
```

Trigger checkpoint creation:
- After every N messages (configurable, default 50)
- On conversation archive
- Manual trigger via API
- Background job for batch processing

### 5. Context Builder
```python
# src/services/checkpoint/context_builder.py
```

Build context from checkpoints:
- Get relevant checkpoints
- Combine summaries
- Include recent messages
- Optimize token usage

## Integration Points

### 1. Message Service Integration
After message processing:
```python
# Check if checkpoint needed
if await checkpoint_service.should_create_checkpoint(conversation_id):
    # Create task for async checkpoint creation
    asyncio.create_task(
        checkpoint_service.create_checkpoint(conversation_id)
    )
```

### 2. Conversation Context Building
When building context for agents:
```python
# Get checkpoint summaries
checkpoint_context = await checkpoint_service.get_checkpoint_context(
    conversation_id,
    max_checkpoints=3
)

# Include in agent input
agent_input["checkpoint_context"] = checkpoint_context
```

### 3. STM Integration
During checkpoint creation:
- Extract important STM entries
- Include in checkpoint
- Promote to LTM if needed

## Checkpoint Configuration

### Configurable Parameters:
```python
CHECKPOINT_CONFIG = {
    "messages_per_checkpoint": 50,
    "max_checkpoints_per_conversation": 20,
    "summary_max_length": 500,
    "key_points_max": 10,
    "entities_max": 20,
    "summarization_model": "gpt-3.5-turbo",
    "batch_processing_enabled": True,
    "batch_size": 10,
}
```

### Environment Variables:
```bash
CHECKPOINT_MESSAGE_THRESHOLD=50
CHECKPOINT_MAX_PER_CONVERSATION=20
CHECKPOINT_SUMMARIZATION_MODEL=gpt-3.5-turbo
CHECKPOINT_ASYNC_PROCESSING=true
CHECKPOINT_BATCH_INTERVAL_MINUTES=5
```

## API Endpoints

### Checkpoint API:
```python
# src/api/v1/conversations/checkpoints.py
```

Endpoints:
```
GET    /api/v1/conversations/{id}/checkpoints      # List checkpoints
POST   /api/v1/conversations/{id}/checkpoint       # Create checkpoint manually
GET    /api/v1/conversations/{id}/checkpoints/{id} # Get checkpoint details
DELETE /api/v1/conversations/{id}/checkpoints/{id} # Delete checkpoint
```

### Response Schemas:
```python
class CheckpointResponse(BaseModel):
    id: UUID
    checkpoint_number: int
    message_count: int
    summary: str
    key_points: List[str]
    entities: List[Entity]
    topics: List[str]
    created_at: datetime

class Entity(BaseModel):
    type: str  # person, org, project, tech
    name: str
    mentions: int
```

## Performance Optimizations

### 1. Async Processing
- Create checkpoints asynchronously
- Don't block message flow
- Use background tasks

### 2. Batch Processing
- Process multiple conversations
- Scheduled batch jobs
- Optimize LLM calls

### 3. Caching
- Cache recent checkpoints
- Invalidate on new checkpoint
- Redis for fast access

### 4. Token Optimization
- Limit message context size
- Compress older checkpoints
- Incremental summaries

## Testing Requirements

### Unit Tests:
- Checkpoint creation logic
- Summary generation
- Entity extraction
- Context building

### Integration Tests:
- Message count triggers
- Async processing
- Error handling
- Performance impact

### Test Scenarios:
1. Reach 50 messages → checkpoint created
2. Manual checkpoint creation
3. Multiple checkpoints in conversation
4. Checkpoint with errors in LLM
5. Concurrent checkpoint creation

## Monitoring & Metrics

### Metrics to Track:
- Checkpoints created per day
- Average processing time
- LLM tokens used
- Error rates
- Storage usage

### Alerts:
- High failure rate
- Slow processing
- Token limit exceeded
- Storage threshold

## Success Criteria

- [ ] Automatic checkpoint every 50 messages
- [ ] Summary generation accurate
- [ ] Entity extraction working
- [ ] Async processing smooth
- [ ] No impact on message latency
- [ ] API endpoints functional
- [ ] Tests passing >80% coverage
- [ ] Performance targets met

## Error Handling

Handle these scenarios:
- LLM timeout during summarization
- Invalid message range
- Concurrent checkpoint creation
- Storage limits exceeded
- Malformed LLM response

## Migration Strategy

For existing conversations:
1. Identify conversations > 50 messages
2. Create initial checkpoints
3. Process in batches
4. Monitor resource usage

## Future Enhancements

Consider for later:
1. Incremental summaries
2. Multi-language support
3. Custom checkpoint intervals
4. Checkpoint compression
5. Smart checkpoint timing
6. Checkpoint search
7. Export checkpoints

## Example Checkpoint Data

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440001",
  "conversation_id": "550e8400-e29b-41d4-a716-446655440000",
  "checkpoint_number": 1,
  "message_count": 50,
  "summary": "User discussed implementing a new authentication system using JWT tokens. Covered security best practices, token expiration strategies, and refresh token implementation.",
  "key_points": [
    "Decided on 15-minute access token expiration",
    "Will implement refresh token rotation",
    "Need to add rate limiting for token endpoints",
    "Chose Redis for token blacklisting"
  ],
  "entities": [
    {"type": "technology", "name": "JWT", "mentions": 12},
    {"type": "technology", "name": "Redis", "mentions": 5},
    {"type": "project", "name": "AuthService", "mentions": 3}
  ],
  "topics": ["authentication", "security", "JWT", "token management"],
  "created_at": "2024-01-20T10:30:00Z"
}