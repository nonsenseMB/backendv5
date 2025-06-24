# Context Management Documentation

## Overview

The context management system provides thread-safe, request-scoped storage for contextual information throughout the application lifecycle. It uses Python's `contextvars` module to ensure proper isolation between concurrent requests.

## Architecture

### Three Types of Context

1. **Request Context** (`src/core/context/request_context.py`)
   - Request-specific information (request ID, method, path, etc.)
   - Authentication details (user ID, session ID, permissions)
   - Request metadata (IP address, user agent, device ID)

2. **Tenant Context** (`src/core/context/tenant_context.py`)
   - Current tenant ID for multi-tenant isolation
   - Thread-safe tenant switching

3. **User Context** (`src/core/context/user_context.py`)
   - User profile information
   - Permissions and roles
   - User preferences and settings

## Request Context

### Data Structure

```python
@dataclass
class RequestContext:
    # Core identifiers
    request_id: str
    user_id: str
    tenant_id: str
    session_id: str
    
    # Authorization data
    permissions: List[str]
    groups: List[str]
    roles: List[str]
    
    # Request metadata
    ip_address: Optional[str]
    user_agent: Optional[str]
    device_id: Optional[str]
    api_version: Optional[str]
    
    # Request details
    method: Optional[str]
    path: Optional[str]
    query_params: Dict[str, Any]
    
    # Timing information
    start_time: datetime
    
    # Additional context
    extra: Dict[str, Any]
```

### Usage Examples

```python
from src.core.context import (
    RequestContext, 
    set_request_context,
    get_request_context,
    update_request_context
)

# Set context
context = RequestContext(
    request_id="req-123",
    user_id="user-456",
    tenant_id="tenant-789",
    session_id="session-abc"
)
set_request_context(context)

# Get context
current = get_request_context()
if current:
    print(f"Request ID: {current.request_id}")

# Update context
update_request_context(
    permissions=["admin"],
    ip_address="192.168.1.1"
)

# Clear context
clear_request_context()
```

## User Context

### Data Structure

```python
@dataclass
class UserContext:
    # Core user information
    user_id: UUID
    email: str
    username: Optional[str]
    full_name: Optional[str]
    
    # User status
    is_active: bool
    is_verified: bool
    is_superuser: bool
    
    # Authentication details
    auth_provider: Optional[str]
    external_id: Optional[str]
    
    # Permissions and roles
    permissions: List[str]
    groups: List[str]
    tenant_roles: Dict[str, str]  # tenant_id -> role
    
    # User preferences
    language: str
    timezone: str
    theme: str
    
    # Additional metadata
    metadata: Dict[str, Any]
```

### Permission Checking

```python
from src.core.context import get_user_context

user = get_user_context()
if user:
    # Check single permission
    if user.has_permission("users:read"):
        # User can read users
        
    # Check any of multiple permissions
    if user.has_any_permission(["users:write", "admin"]):
        # User can write or is admin
        
    # Check all permissions
    if user.has_all_permissions(["users:read", "users:write"]):
        # User has both permissions
```

## Context Managers

For temporary context switching (useful in background tasks):

```python
from src.core.context import RequestContextManager, UserContextManager

# Temporarily switch request context
temp_context = RequestContext(...)
with RequestContextManager(temp_context):
    # Code here runs with temp_context
    pass
# Original context restored

# Temporarily switch user context
temp_user = UserContext(...)
with UserContextManager(temp_user):
    # Code here runs as temp_user
    pass
# Original user restored
```

## Integration with Logging

The logging system automatically includes context information in all log entries:

```python
from src.core.logging import get_logger

logger = get_logger(__name__)

# This will automatically include request_id, user_id, tenant_id, etc.
logger.info("Processing request")
```

Log output example:
```json
{
    "timestamp": "2024-01-20T10:30:00Z",
    "level": "INFO",
    "message": "Processing request",
    "request_id": "req-123",
    "user_id": "user-456",
    "tenant_id": "tenant-789",
    "method": "POST",
    "path": "/api/users"
}
```

## Middleware Integration

### Context Middleware (`src/api/middleware/context.py`)

The context middleware:
1. Generates or extracts request ID
2. Creates RequestContext from request state
3. Sets up UserContext if authenticated
4. Ensures cleanup after request

### Middleware Order

The correct middleware order in `main.py`:

```python
# 1. Authentication middleware (sets request.state.user_id, etc.)
@app.middleware("http")
async def auth_middleware(request, call_next):
    return await jwt_validation_middleware(request, call_next)

# 2. Tenant middleware (sets request.state.tenant_id)
@app.middleware("http")
async def tenant_middleware(request, call_next):
    return await tenant_injection_middleware(request, call_next)

# 3. Context middleware (creates contexts from request.state)
@app.middleware("http")
async def context_middleware(request, call_next):
    return await request_context_middleware(request, call_next)

# 4. Other middleware can now use context
```

## Thread Safety

The context system is thread-safe and async-safe:

```python
import asyncio

async def task1():
    set_request_context(RequestContext(request_id="task1", ...))
    await asyncio.sleep(0.1)
    # Still has task1 context

async def task2():
    set_request_context(RequestContext(request_id="task2", ...))
    await asyncio.sleep(0.1)
    # Still has task2 context

# Run concurrently - contexts don't interfere
await asyncio.gather(task1(), task2())
```

## Best Practices

1. **Always use context managers for temporary switches**
   ```python
   with RequestContextManager(temp_context):
       # Temporary context
   ```

2. **Clear context in finally blocks**
   ```python
   try:
       set_request_context(context)
       # Process request
   finally:
       clear_request_context()
   ```

3. **Use require_* functions when context is mandatory**
   ```python
   context = require_request_context()  # Raises if not set
   ```

4. **Don't store sensitive data in context**
   - Context may be logged
   - Use context for IDs, not passwords or tokens

5. **Update context as needed**
   ```python
   # Add information as it becomes available
   update_request_context(
       permissions=user_permissions,
       groups=user_groups
   )
   ```

## Performance Considerations

- Context lookups are O(1) - very fast
- Context is stored in thread-local storage
- No database queries required
- Minimal memory overhead per request

## Testing

When testing code that uses context:

```python
import pytest
from src.core.context import RequestContext, set_request_context

@pytest.fixture
def request_context():
    context = RequestContext(
        request_id="test-123",
        user_id="test-user",
        tenant_id="test-tenant",
        session_id="test-session"
    )
    set_request_context(context)
    yield context
    clear_request_context()

def test_with_context(request_context):
    # Test code has access to context
    assert get_request_context().request_id == "test-123"
```

## Troubleshooting

### Context Not Available

If `get_request_context()` returns None:
1. Check middleware order - context middleware must run after auth
2. Verify middleware is registered in `main.py`
3. Check if context was cleared prematurely

### Context Leaking Between Requests

If context from one request appears in another:
1. Ensure middleware clears context in finally block
2. Check for missing `clear_request_context()` calls
3. Verify no global context storage

### Performance Issues

If context operations are slow:
1. Check for recursive context updates
2. Verify no blocking operations in context setup
3. Review context data size - avoid storing large objects