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

### Task 111: Implement JWT Extraction and Validation Middleware ✅ COMPLETED
**Priority**: Critical
**Effort**: 1 day
**Description**: Create middleware to extract and validate JWT tokens from requests
**Status**: ✅ 100% Functional - NO mocks, NO workarounds

**Implementation**:
```python
src/api/middleware/auth.py
```

**Key Features**:
- Extract Bearer token from Authorization header ✅
- Validate JWT signature and claims ✅
- Handle token refresh for expired tokens ✅
- Skip authentication for public endpoints ✅

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
- [x] Extract tokens from headers ✅ (Bearer token from Authorization header AND cookies)
- [x] Validate against JWKS ✅ (via TokenValidator with JWKSCache)
- [x] Set request state ✅ (user_id, tenant_id, session_id, permissions, groups, token_claims)
- [x] Handle auth errors with 401/403 ✅ (proper error responses with detail messages)

**Additional Achievements**:
- [x] RSA key-based JWT signing (RS256) with real keys
- [x] Database-backed UserService (no mock UUIDs)
- [x] Redis SessionService with fallback
- [x] Full token refresh flow implemented
- [x] Supports both internal JWTs and Authentik tokens
- [x] Production-ready with proper error handling

### Task 112: Create Tenant Context Injection Middleware ✅ COMPLETED
**Priority**: Critical
**Effort**: 1 day
**Description**: Inject tenant context into all requests for multi-tenant isolation
**Status**: ✅ 100% Functional - Thread-safe context isolation

**Implementation**:
```python
src/api/middleware/tenant.py
src/core/context/tenant_context.py
src/infrastructure/database/tenant_aware.py
```

**Key Features**:
- Extract tenant from JWT claims or header ✅
- Validate user-tenant membership ✅
- Set tenant context using contextvars ✅
- Apply to database queries automatically ✅

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
- [x] Tenant extracted from JWT/headers ✅ (JWT claims, headers, query params)
- [x] Context available throughout request ✅ (contextvars thread-safe)
- [x] Database queries filtered by tenant ✅ (TenantAwareRepository integration)
- [x] Proper cleanup after request ✅ (finally block ensures cleanup)

**Additional Achievements**:
- [x] TenantContextManager for programmatic context switching
- [x] Automatic tenant context injection in TenantAwareRepository
- [x] Multi-source tenant extraction (JWT, headers, query params)
- [x] Thread-safe context isolation verified with tests
- [x] Production-ready error handling and validation

### Task 113: Build FastAPI Dependencies ✅ COMPLETED
**Priority**: Critical
**Effort**: 1.5 days
**Description**: Create reusable dependencies for auth requirements
**Status**: ✅ 100% Functional - Production ready

**Implementation**:
```python
src/api/dependencies/
├── __init__.py        ✅
├── auth.py            ✅ # get_current_user, require_auth, get_optional_user, etc.
├── tenant.py          ✅ # get_current_tenant, require_tenant_role, get_tenant_user
├── permissions.py     ✅ # require_permission, require_any/all_permissions
└── session.py         ✅ # get_current_session, invalidate_session, get_session_metadata
```

**Key Dependencies Implemented**:
```python
# Authentication dependencies
- get_current_user_id() -> UUID
- get_current_user() -> User (with DB lookup)
- get_optional_user() -> Optional[User]
- require_auth() -> UUID
- get_current_active_user() -> User
- get_current_verified_user() -> User

# Tenant dependencies  
- get_current_tenant() -> Tenant
- get_tenant_user() -> TenantUser
- require_tenant_role(role: str) -> Dependency
- ensure_tenant_context() -> Tenant

# Permission dependencies
- require_permission(permission: str) -> Dependency
- require_any_permission(permissions: List[str]) -> Dependency
- require_all_permissions(permissions: List[str]) -> Dependency
- require_tenant_permission(permission: str) -> Dependency

# Session dependencies
- get_current_session() -> SessionInfo
- get_session_metadata() -> dict
- invalidate_current_session() -> bool
```

**Success Criteria**:
- [x] Clean dependency injection ✅
- [x] Reusable across endpoints ✅
- [x] Clear error messages ✅
- [x] Type-safe implementations ✅

**Additional Achievements**:
- [x] Full integration with JWT middleware
- [x] Support for wildcard permissions (e.g., users:*)
- [x] Tenant role hierarchy (owner > admin > member > viewer)
- [x] Comprehensive unit tests
- [x] Production-ready error handling
- [x] Documentation with usage examples

### Task 114: Implement Request Context Management ✅ COMPLETED
**Priority**: High
**Effort**: 1 day
**Description**: Manage request-scoped context using contextvars
**Status**: ✅ 100% Functional - Thread-safe context management

**Implementation**:
```python
src/core/context/
├── __init__.py         ✅ # Enhanced with all exports
├── request_context.py  ✅ # Enhanced RequestContext with full fields
├── tenant_context.py   ✅ # Already existed
└── user_context.py     ✅ # New comprehensive UserContext
```

**Context Structure Implemented**:
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
    
    # Timing and extras
    start_time: datetime
    extra: Dict[str, Any]
```

**Key Features**:
- Thread-safe context storage using contextvars
- RequestContextManager for temporary switching
- UserContext with permission checking methods
- Context middleware for automatic setup/cleanup
- Full logging integration

**Integration Points**:
- [x] Logging (automatic context injection) ✅
- [x] Database queries (tenant filtering) ✅
- [x] Audit trails (user tracking) ✅
- [x] Performance monitoring ✅

**Success Criteria**:
- [x] Context available throughout request ✅
- [x] Thread-safe implementation ✅
- [x] Integration with logging ✅
- [x] Clean context lifecycle ✅

**Additional Achievements**:
- [x] Comprehensive unit tests with thread-safety verification
- [x] Context managers for temporary switching
- [x] User permission checking with wildcard support
- [x] Full documentation in docs/core/context-management.md
- [x] Production-ready with proper error handling

### Task 115: Add Security Headers and CORS Configuration ✅ COMPLETED
**Priority**: Medium
**Effort**: 0.5 day
**Description**: Configure security headers and CORS for API protection
**Status**: ✅ 100% Functional - Production-ready security

**Implementation**:
```python
src/api/middleware/security.py   ✅ # SecurityHeadersMiddleware
src/api/middleware/cors.py       ✅ # TenantAwareCORSMiddleware  
src/core/config/cors.py          ✅ # CORSConfig with caching
```

**Security Headers Implemented**:
- X-Content-Type-Options: nosniff ✅
- X-Frame-Options: DENY ✅
- X-XSS-Protection: 1; mode=block ✅
- Strict-Transport-Security (HTTPS only) ✅
- Content-Security-Policy (with nonce support) ✅
- Referrer-Policy: strict-origin-when-cross-origin ✅
- Permissions-Policy (restrictive by default) ✅

**CORS Configuration**:
```python
# Tenant-aware CORS with caching
class CORSConfig:
    - Global origins from settings
    - Wildcard pattern support (*.example.com)
    - Per-tenant origins from database
    - 5-minute cache TTL
    - Development mode auto-allows localhost

# Custom middleware replaces standard CORSMiddleware
@app.middleware("http")
async def cors(request: Request, call_next):
    return await tenant_aware_cors_middleware(request, call_next)
```

**Success Criteria**:
- [x] Security headers on all responses ✅
- [x] CORS properly configured ✅
- [x] Per-tenant CORS rules ✅
- [x] WebSocket CORS support ✅

**Additional Achievements**:
- [x] Wildcard origin pattern matching
- [x] Tenant CORS caching for performance
- [x] Proper preflight (OPTIONS) handling
- [x] CSP with report-uri support
- [x] Comprehensive unit tests
- [x] Full documentation and integration guide

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