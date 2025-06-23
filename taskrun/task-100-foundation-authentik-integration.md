# Sprint 100: Foundation & Authentik Integration

## Sprint Goal
Set up core authentication infrastructure and Authentik client integration as the foundation for all authentication features.

## Duration
Week 1-2 (10 working days)

## Current State
- The Authentik server is already set up
- Authentik`s deployment is based on BluePrints 
- Blueprint stored in: Infra/authentik/blueprints
- .env contains all passowrd secrets and users for authentik
- it is important to use 127.0.0.1 and NOT localhost.

## Prerequisites
- Backend database models in place
- Basic FastAPI application structure

## Tasks

### Task 101: Configure Authentik Integration Service and API Client
**Priority**: Critical
**Effort**: 1 day
**Description**: Create the base Authentik client service for API communication

**Implementation**:
```python
src/infrastructure/auth/
├── __init__.py
├── authentik_client.py     # Core Authentik API client
├── config.py              # Authentik configuration
└── exceptions.py          # Auth-specific exceptions
```

**Key Components**:
- HTTP client with retry logic
- API authentication with admin token
- Tenant-specific configuration support
- Error handling for Authentik API

**Success Criteria**:
- [ ] Can connect to Authentik API
- [ ] Handle API errors gracefully
- [ ] Configuration from environment variables
- [ ] Unit tests for client methods

### Task 102: Implement JWT Token Validation and JWKS Caching
**Priority**: Critical
**Effort**: 1 day
**Description**: Build JWT validation with public key caching from Authentik JWKS endpoint

**Implementation**:
```python
src/infrastructure/auth/token_validator.py
src/infrastructure/auth/jwks_cache.py
```

**Key Components**:
- JWKS fetching and caching (TTL: 1 hour)
- JWT signature validation
- Claims extraction and validation
- Token expiry handling

**Success Criteria**:
- [ ] Validate Authentik-issued JWTs
- [ ] Cache JWKS for performance
- [ ] Handle key rotation
- [ ] Comprehensive error messages

### Task 103: Create Token Exchange Service
**Priority**: Critical
**Effort**: 2 days
**Description**: Exchange Authentik tokens for internal API tokens

**Implementation**:
```python
src/infrastructure/auth/token_exchange.py
src/core/auth/jwt_manager.py
```

**Key Features**:
- Exchange Authentik token for internal JWT
- Create user record if not exists
- Handle tenant assignment
- Session tracking

**API Endpoint**:
```
POST /api/v1/auth/token/exchange
{
    "authentik_token": "string",
    "tenant_id": "uuid"
}
```

**Success Criteria**:
- [ ] Exchange tokens successfully
- [ ] Create/update user records
- [ ] Maintain session consistency
- [ ] Secure token generation

### Task 104: Set Up Environment Configuration and Security Checks
**Priority**: High
**Effort**: 0.5 day
**Description**: Configure environment variables and implement startup security checks

**Configuration**:
```env
# Authentik Configuration
AUTHENTIK_URL=https://auth.example.com
AUTHENTIK_TOKEN=<admin-token>
AUTHENTIK_PUBLIC_KEY_URL=/application/o/nai-platform/jwks/

# JWT Configuration
JWT_ALGORITHM=RS256
JWT_ISSUER=https://auth.example.com/application/o/nai-platform/
JWT_AUDIENCE=nai-platform
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
JWT_REFRESH_TOKEN_EXPIRE_DAYS=30

# Security Flags
DEVICE_AUTH_REQUIRED=true
PASSWORD_AUTH_ENABLED=false
WEBAUTHN_USER_VERIFICATION=required
```

**Security Checks**:
```python
src/core/auth/security_checks.py
# Validate no password fields in database
# Ensure device auth is required
# Verify Authentik connectivity
```

**Success Criteria**:
- [ ] All required env vars documented
- [ ] Startup checks prevent insecure configs
- [ ] Configuration validation with Pydantic
- [ ] Clear error messages for misconfigs

### Task 105: Create Base Authentication Exceptions and Error Handling
**Priority**: Medium
**Effort**: 0.5 day
**Description**: Define authentication exception hierarchy and error responses

**Implementation**:
```python
src/core/auth/exceptions.py
src/api/exceptions/auth_handlers.py
```

**Exception Types**:
- `AuthenticationError` - Base exception
- `InvalidTokenError` - JWT validation failed
- `TokenExpiredError` - Token has expired
- `InsufficientPermissionsError` - Authorization failed
- `TenantAccessDeniedError` - Tenant isolation violation
- `DeviceNotTrustedError` - Device auth failed

**Success Criteria**:
- [ ] Clear exception hierarchy
- [ ] Consistent error responses
- [ ] Proper HTTP status codes
- [ ] Security-conscious error messages

## Dependencies

```toml
# Add to pyproject.toml
python-jose[cryptography] = "^3.3.0"  # JWT handling
httpx = "^0.27.0"                      # HTTP client
tenacity = "^8.2.0"                    # Retry logic
cachetools = "^5.3.0"                  # JWKS caching
```

## Testing Requirements

### Unit Tests
- Authentik client methods
- JWT validation scenarios
- Token exchange logic
- Configuration validation

### Integration Tests
- Full Authentik API communication
- Token exchange flow
- Error handling paths

### Security Tests
- Invalid token rejection
- Expired token handling
- Missing claims validation
- Signature verification

## Documentation Deliverables
- Authentik integration guide
- Environment setup documentation
- Token flow sequence diagrams
- Error handling guide

## Risks & Mitigations
1. **Risk**: Authentik downtime affects all auth
   **Mitigation**: Implement circuit breaker pattern

2. **Risk**: JWKS cache invalidation
   **Mitigation**: Manual cache refresh endpoint

3. **Risk**: Token exchange performance
   **Mitigation**: Connection pooling, async operations

## Definition of Done
- [ ] All code has unit tests (>90% coverage)
- [ ] Integration tests passing
- [ ] Security checks implemented
- [ ] Documentation complete
- [ ] Code review approved
- [ ] No passwords in codebase
- [ ] Performance benchmarks met (<50ms)

## Next Sprint Dependencies
This sprint provides the foundation for:
- Sprint 110: Middleware implementation
- Sprint 120: Device authentication
- All subsequent auth features