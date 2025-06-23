# Next Implementation Task: Authentication & Authorization

## Task: Implement Authentik-based Authentication System

### Priority: HIGH - This is the foundation for all other features

### Rationale:
- All API endpoints need authentication
- Multi-tenant isolation requires user/tenant context
- WebSocket connections need JWT-based auth
- Permission checks are required for all operations

### Implementation Scope:

#### 1. Authentik Integration Service
```python
src/infrastructure/auth/
├── __init__.py
├── authentik_client.py     # Authentik API client
├── token_validator.py      # JWT validation
└── device_auth.py         # Device-based authentication
```

#### 2. Authentication Middleware
```python
src/api/middleware/
├── __init__.py
├── auth.py                # JWT extraction & validation
├── tenant.py              # Tenant context injection
└── permissions.py         # Permission checking
```

#### 3. Dependency Injection
```python
src/api/dependencies/
├── __init__.py
├── auth.py                # get_current_user, require_auth
├── tenant.py              # get_current_tenant
└── permissions.py         # require_permission
```

#### 4. Auth API Endpoints
```python
src/api/v1/auth/
├── __init__.py
├── router.py              # Auth routes
├── schemas.py             # Pydantic models
└── endpoints.py           # Login, device registration, etc.
```

### Key Features to Implement:

1. **JWT Token Validation**
   - Validate Authentik-issued JWTs
   - Extract user claims (external_id, email, groups)
   - Handle token refresh

2. **Device Registration Flow**
   - WebAuthn device registration
   - Passkey support
   - Device trust scoring

3. **Tenant Context**
   - Extract tenant from JWT claims or header
   - Inject into all requests
   - Validate user-tenant membership

4. **Permission System**
   - Role-based (Admin, Member, Viewer)
   - Resource-based (document permissions)
   - Tenant-scoped permissions

5. **WebSocket Authentication**
   - JWT in connection params
   - Periodic token refresh
   - Connection state management

### API Endpoints:

```
POST   /api/v1/auth/device/register    # Register new device
POST   /api/v1/auth/device/verify      # Verify device (WebAuthn)
POST   /api/v1/auth/token/refresh      # Refresh JWT token
GET    /api/v1/auth/me                 # Current user info
GET    /api/v1/auth/me/tenants         # User's tenants
POST   /api/v1/auth/tenant/switch      # Switch active tenant
DELETE /api/v1/auth/device/{device_id} # Remove device
```

### Dependencies:

```toml
# Add to pyproject.toml
python-jose[cryptography] = "^3.3.0"  # JWT handling
httpx = "^0.25.0"                      # Authentik API client
webauthn = "^2.0.0"                    # WebAuthn support
```

### Environment Variables:

```env
# Authentik Configuration
AUTHENTIK_URL=https://auth.example.com
AUTHENTIK_TOKEN=<admin-token>
AUTHENTIK_PUBLIC_KEY_URL=/application/o/nai-platform/jwks/

# JWT Configuration
JWT_ALGORITHM=RS256
JWT_ISSUER=https://auth.example.com/application/o/nai-platform/
JWT_AUDIENCE=nai-platform
```

### Testing Requirements:

1. **Unit Tests**
   - JWT validation (valid, expired, wrong signature)
   - Permission checks
   - Device registration

2. **Integration Tests**
   - Full auth flow
   - Tenant switching
   - WebSocket auth

3. **Security Tests**
   - Invalid tokens
   - Tenant isolation
   - Permission bypasses

### Success Criteria:

- [ ] All API endpoints require authentication
- [ ] Multi-tenant isolation is enforced
- [ ] WebSocket connections are authenticated
- [ ] Device-based auth works (WebAuthn)
- [ ] Proper error messages for auth failures
- [ ] Comprehensive test coverage
- [ ] Documentation for auth flow

### Alternative Considerations:

If you prefer to start with something simpler before auth:

1. **Basic CRUD APIs** (without auth) - Quick wins but insecure
2. **WebSocket Infrastructure** - But needs auth anyway
3. **Business Logic Layer** - But needs user context

However, I strongly recommend auth first as it's foundational.