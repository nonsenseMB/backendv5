# Sprint 110: Authentication Middleware & Dependencies

## Sprint Goal
Build the middleware layer for request authentication and create FastAPI dependencies for auth enforcement across all endpoints.

## Duration
Week 3 (5 working days)

## Prerequisites
- Sprint 100 completed (Authentik integration)
- JWT validation working
- Token exchange service operational

## Tasks

### Task 111: Implement JWT Extraction and Validation Middleware
**Priority**: Critical
**Effort**: 1 day
**Description**: Create middleware to extract and validate JWT tokens from requests

**Implementation**:
```python
src/api/middleware/auth.py
```

**Key Features**:
- Extract Bearer token from Authorization header
- Validate JWT signature and claims
- Handle token refresh for expired tokens
- Skip authentication for public endpoints

**Code Structure**:
```python
@app.middleware("http")
async def jwt_validation_middleware(request: Request, call_next):
    # Skip public endpoints
    if request.url.path in PUBLIC_ENDPOINTS:
        return await call_next(request)
    
    # Extract and validate token
    # Set request.state.user_id, tenant_id, session_id
    # Handle errors appropriately
```

**Success Criteria**:
- [ ] Extract tokens from headers
- [ ] Validate against JWKS
- [ ] Set request state
- [ ] Handle auth errors with 401/403

### Task 112: Create Tenant Context Injection Middleware
**Priority**: Critical
**Effort**: 1 day
**Description**: Inject tenant context into all requests for multi-tenant isolation

**Implementation**:
```python
src/api/middleware/tenant.py
src/core/context/tenant_context.py
```

**Key Features**:
- Extract tenant from JWT claims or header
- Validate user-tenant membership
- Set tenant context using contextvars
- Apply to database queries automatically

**Context Management**:
```python
# Using contextvars for thread-safe context
tenant_context: ContextVar[str] = ContextVar('tenant_context')

async def tenant_middleware(request: Request, call_next):
    tenant_id = extract_tenant_id(request)
    tenant_context.set(tenant_id)
    try:
        response = await call_next(request)
    finally:
        tenant_context.set(None)
    return response
```

**Success Criteria**:
- [ ] Tenant extracted from JWT/headers
- [ ] Context available throughout request
- [ ] Database queries filtered by tenant
- [ ] Proper cleanup after request

### Task 113: Build FastAPI Dependencies
**Priority**: Critical
**Effort**: 1.5 days
**Description**: Create reusable dependencies for auth requirements

**Implementation**:
```python
src/api/dependencies/
├── __init__.py
├── auth.py            # get_current_user, require_auth
├── tenant.py          # get_current_tenant
├── permissions.py     # require_permission
└── session.py         # get_current_session
```

**Key Dependencies**:
```python
# Get current authenticated user
async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> User:
    user_id = request.state.user_id
    return await user_repository.get(user_id)

# Require authentication
def require_auth(request: Request) -> str:
    if not hasattr(request.state, 'user_id'):
        raise HTTPException(401, "Authentication required")
    return request.state.user_id

# Require specific permission
def require_permission(permission: str):
    async def check_permission(
        user: User = Depends(get_current_user)
    ):
        if not await has_permission(user, permission):
            raise HTTPException(403, "Insufficient permissions")
    return check_permission
```

**Success Criteria**:
- [ ] Clean dependency injection
- [ ] Reusable across endpoints
- [ ] Clear error messages
- [ ] Type-safe implementations

### Task 114: Implement Request Context Management
**Priority**: High
**Effort**: 1 day
**Description**: Manage request-scoped context using contextvars

**Implementation**:
```python
src/core/context/
├── __init__.py
├── request_context.py
├── tenant_context.py
└── user_context.py
```

**Context Structure**:
```python
@dataclass
class RequestContext:
    request_id: str
    user_id: str
    tenant_id: str
    session_id: str
    permissions: List[str]
    device_id: Optional[str]
    
# Thread-safe context storage
request_context: ContextVar[RequestContext] = ContextVar('request_context')
```

**Integration Points**:
- Logging (automatic context injection)
- Database queries (tenant filtering)
- Audit trails (user tracking)
- Performance monitoring

**Success Criteria**:
- [ ] Context available throughout request
- [ ] Thread-safe implementation
- [ ] Integration with logging
- [ ] Clean context lifecycle

### Task 115: Add Security Headers and CORS Configuration
**Priority**: Medium
**Effort**: 0.5 day
**Description**: Configure security headers and CORS for API protection

**Implementation**:
```python
src/api/middleware/security.py
src/core/config/cors.py
```

**Security Headers**:
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block
- Strict-Transport-Security
- Content-Security-Policy

**CORS Configuration**:
```python
# Tenant-aware CORS
async def get_allowed_origins(tenant_id: str) -> List[str]:
    # Fetch tenant-specific allowed origins
    pass

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Success Criteria**:
- [ ] Security headers on all responses
- [ ] CORS properly configured
- [ ] Per-tenant CORS rules
- [ ] WebSocket CORS support

## Testing Requirements

### Unit Tests
- JWT extraction from various header formats
- Tenant context injection
- Permission checking logic
- Dependency injection

### Integration Tests
- Full request flow with auth
- Tenant isolation verification
- Error handling paths
- Context propagation

### Security Tests
- Missing token rejection
- Invalid token handling
- Tenant isolation enforcement
- CORS policy validation

## Performance Considerations
- Context lookup optimization
- Dependency caching where appropriate
- Minimize database queries
- Async everywhere

## Documentation Deliverables
- Middleware architecture diagram
- Dependency usage examples
- Context management guide
- Security headers documentation

## Risks & Mitigations
1. **Risk**: Performance overhead from middleware
   **Mitigation**: Optimize hot paths, use caching

2. **Risk**: Context leakage between requests
   **Mitigation**: Proper cleanup in finally blocks

3. **Risk**: Complex dependency chains
   **Mitigation**: Clear documentation, simple interfaces

## Definition of Done
- [ ] All middleware integrated
- [ ] Dependencies documented
- [ ] Tests achieving >90% coverage
- [ ] Performance benchmarks met
- [ ] Security review passed
- [ ] No authentication bypasses
- [ ] Clean error handling

## Next Sprint Dependencies
This sprint enables:
- Sprint 120: Device authentication endpoints
- Sprint 130: Permission system
- All protected API endpoints