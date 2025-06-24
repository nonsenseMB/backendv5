# Sprint 160: Testing & Security Hardening

## Sprint Goal
Implement comprehensive testing for all authentication components, conduct security validation, and add hardening measures like rate limiting and brute force protection.

## Duration
Week 9 (5 working days)

## Prerequisites
- Sprints 100-150 completed
- All auth features implemented
- Basic testing framework in place

## Tasks

### Task 161: Write Unit Tests for All Auth Components
**Priority**: Critical
**Effort**: 1.5 days
**Description**: Comprehensive unit test coverage for authentication system

**Implementation**:
```python
tests/unit/auth/
├── test_authentik_client.py
├── test_jwt_validation.py
├── test_token_exchange.py
├── test_device_auth.py
├── test_permissions.py
├── test_tenant_membership.py
└── test_session_manager.py
```

**Key Test Cases**:

```python
# test_jwt_validation.py
class TestJWTValidation:
    async def test_valid_token_decode(self):
        """Test decoding valid JWT token"""
        token = create_test_token(user_id="123", tenant_id="456")
        payload = await jwt_validator.decode_token(token)
        assert payload["sub"] == "123"
        assert payload["tenant_id"] == "456"
        
    async def test_expired_token_rejection(self):
        """Test expired token is rejected"""
        token = create_test_token(exp=datetime.utcnow() - timedelta(hours=1))
        with pytest.raises(TokenExpiredError):
            await jwt_validator.decode_token(token)
            
    async def test_invalid_signature_rejection(self):
        """Test token with invalid signature"""
        token = create_test_token()
        # Tamper with token
        parts = token.split(".")
        parts[2] = "invalid_signature"
        invalid_token = ".".join(parts)
        
        with pytest.raises(InvalidTokenError):
            await jwt_validator.decode_token(invalid_token)
            
    async def test_missing_claims_rejection(self):
        """Test token missing required claims"""
        token = create_test_token(exclude_claims=["tenant_id"])
        with pytest.raises(InvalidTokenError, match="Missing required claim"):
            await jwt_validator.decode_token(token)
```

```python
# test_permissions.py
class TestPermissions:
    async def test_role_permission_check(self):
        """Test role-based permission checking"""
        user = create_test_user(role="admin")
        assert await check_permission(user.id, "tenant.manage") is True
        assert await check_permission(user.id, "nonexistent") is False
        
    async def test_resource_permission_check(self):
        """Test resource-level permissions"""
        user = create_test_user()
        resource_id = uuid4()
        
        # Grant permission
        await grant_resource_permission(
            user.id, "document", resource_id, "read"
        )
        
        # Check permission
        assert await check_resource_permission(
            user.id, "document", resource_id, "read"
        ) is True
        assert await check_resource_permission(
            user.id, "document", resource_id, "write"
        ) is False
            
    async def test_tenant_isolation(self):
        """Test permissions are tenant-isolated"""
        user = create_test_user(tenant_id="tenant1")
        resource = create_test_resource(tenant_id="tenant2")
        
        with pytest.raises(TenantAccessDeniedError):
            await check_resource_permission(
                user.id, "document", resource.id, "read"
            )
```

**Test Coverage Requirements**:
- JWT validation edge cases
- Permission calculation logic
- Device authentication flows
- Session management
- Tenant isolation
- WebSocket auth

**Success Criteria**:
- [ ] >90% code coverage
- [ ] All edge cases tested
- [ ] Mocked external dependencies
- [ ] Fast test execution

### Task 162: Create Integration Tests for Auth Flows
**Priority**: Critical
**Effort**: 1.5 days
**Description**: End-to-end testing of authentication flows

**Implementation**:
```python
tests/integration/auth/
├── test_login_flow.py
├── test_device_registration_flow.py
├── test_tenant_switching_flow.py
├── test_permission_flow.py
└── test_websocket_auth_flow.py
```

**Integration Test Examples**:

```python
# test_login_flow.py
class TestLoginFlow:
    async def test_complete_webauthn_login(self, client, test_db):
        """Test complete WebAuthn login flow"""
        # 1. Create user with device
        user = await create_test_user_with_device()
        
        # 2. Request login challenge
        response = await client.post(
            "/api/v1/auth/device/login/options",
            json={"user_id": str(user.id)}
        )
        assert response.status_code == 200
        challenge = response.json()["challenge"]
        
        # 3. Simulate WebAuthn response
        webauthn_response = create_mock_webauthn_response(
            user.device, challenge
        )
        
        # 4. Complete login
        response = await client.post(
            "/api/v1/auth/device/login",
            json=webauthn_response
        )
        assert response.status_code == 200
        tokens = response.json()
        
        # 5. Verify tokens work
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        response = await client.get("/api/v1/users/me", headers=headers)
        assert response.status_code == 200
        assert response.json()["id"] == str(user.id)
```

```python
# test_tenant_switching_flow.py
class TestTenantSwitching:
    async def test_tenant_switch_flow(self, client, test_db):
        """Test switching between tenants"""
        # Create user with multiple tenants
        user = await create_test_user()
        tenant1 = await create_test_tenant("Tenant 1")
        tenant2 = await create_test_tenant("Tenant 2")
        await add_user_to_tenant(user, tenant1, "admin")
        await add_user_to_tenant(user, tenant2, "member")
        
        # Login with tenant1
        tokens = await login_user(client, user, tenant1)
        
        # List available tenants
        response = await client.get(
            "/api/v1/users/me/tenants",
            headers=auth_headers(tokens)
        )
        assert len(response.json()) == 2
        
        # Switch to tenant2
        response = await client.post(
            "/api/v1/users/me/tenant/switch",
            json={"tenant_id": str(tenant2.id)},
            headers=auth_headers(tokens)
        )
        assert response.status_code == 200
        new_tokens = response.json()
        
        # Verify new context
        response = await client.get(
            "/api/v1/users/me/tenant/current",
            headers=auth_headers(new_tokens)
        )
        assert response.json()["tenant_id"] == str(tenant2.id)
        assert response.json()["user_role"] == "member"
```

**Success Criteria**:
- [ ] All flows tested E2E
- [ ] Database state verified
- [ ] Error paths tested
- [ ] Performance acceptable

### Task 163: Implement Security Test Suite
**Priority**: Critical
**Effort**: 1 day
**Description**: Security-focused tests and penetration testing

**Implementation**:
```python
tests/security/
├── test_authentication_bypass.py
├── test_authorization_bypass.py
├── test_tenant_isolation.py
├── test_injection_attacks.py
├── test_rate_limiting.py
└── test_session_security.py
```

**Security Test Cases**:

```python
# test_authentication_bypass.py
class TestAuthenticationBypass:
    async def test_no_token_rejection(self, client):
        """Ensure requests without tokens are rejected"""
        response = await client.get("/api/v1/users/me")
        assert response.status_code == 401
        
    async def test_malformed_token_rejection(self, client):
        """Test various malformed tokens"""
        malformed_tokens = [
            "not.a.token",
            "Bearer ",
            "eyJ" + "a" * 100,
            base64.b64encode(b"fake").decode()
        ]
        
        for token in malformed_tokens:
            response = await client.get(
                "/api/v1/users/me",
                headers={"Authorization": f"Bearer {token}"}
            )
            assert response.status_code == 401
            
    async def test_algorithm_confusion_attack(self, client):
        """Test JWT algorithm confusion attack"""
        # Create token with 'none' algorithm
        header = {"alg": "none", "typ": "JWT"}
        payload = {"sub": "admin", "tenant_id": "123"}
        
        token = (
            base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=") +
            "." +
            base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=") +
            "."
        )
        
        response = await client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 401
```

```python
# test_tenant_isolation.py
class TestTenantIsolation:
    async def test_cross_tenant_resource_access(self, client, test_db):
        """Ensure users cannot access other tenant resources"""
        # Create two tenants with users
        tenant1, user1 = await create_tenant_with_user()
        tenant2, user2 = await create_tenant_with_user()
        
        # Create resource in tenant1
        resource = await create_test_resource(tenant1)
        
        # Try to access from tenant2
        tokens = await login_user(client, user2, tenant2)
        response = await client.get(
            f"/api/v1/resources/{resource.id}",
            headers=auth_headers(tokens)
        )
        assert response.status_code == 403
        
    async def test_tenant_id_injection(self, client, test_db):
        """Test tenant_id cannot be injected via headers"""
        user = await create_test_user()
        tokens = await login_user(client, user)
        
        # Try to inject different tenant_id
        headers = auth_headers(tokens)
        headers["X-Tenant-ID"] = str(uuid4())
        
        response = await client.get("/api/v1/users/me", headers=headers)
        # Should use tenant from JWT, not header
        assert response.json()["tenant_id"] == str(user.tenant_id)
```

**Penetration Test Checklist**:
- [ ] SQL injection attempts
- [ ] JWT tampering
- [ ] Privilege escalation
- [ ] Session fixation
- [ ] CSRF attacks
- [ ] XSS attempts
- [ ] Directory traversal
- [ ] Rate limit bypasses

**Success Criteria**:
- [ ] No security bypasses
- [ ] Proper error handling
- [ ] No information leakage
- [ ] Audit logs generated

### Task 164: Add Rate Limiting and Brute Force Protection
**Priority**: High
**Effort**: 1 day
**Description**: Implement rate limiting and anti-brute force measures

**Implementation**:
```python
src/api/middleware/rate_limiting.py
src/core/security/brute_force_protection.py
```

**Rate Limiter Implementation**:
```python
class RateLimiter:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.limits = {
            # endpoint: (requests, window_seconds)
            "/api/v1/auth/device/login": (5, 300),  # 5 per 5 min
            "/api/v1/auth/token/refresh": (10, 60),  # 10 per min
            "/api/v1/auth/device/register": (3, 3600),  # 3 per hour
            "default": (100, 60)  # 100 per min default
        }
        
    async def check_rate_limit(
        self, 
        identifier: str,  # IP or user_id
        endpoint: str
    ) -> Tuple[bool, Optional[int]]:
        """Check if request is within rate limits"""
        limit, window = self.limits.get(endpoint, self.limits["default"])
        
        key = f"rate_limit:{identifier}:{endpoint}"
        
        # Use sliding window counter
        now = time.time()
        window_start = now - window
        
        # Remove old entries
        await self.redis.zremrangebyscore(key, 0, window_start)
        
        # Count requests in window
        count = await self.redis.zcard(key)
        
        if count >= limit:
            # Calculate retry after
            oldest = await self.redis.zrange(key, 0, 0, withscores=True)
            if oldest:
                retry_after = int(oldest[0][1] + window - now)
                return False, retry_after
            return False, window
            
        # Add current request
        await self.redis.zadd(key, {str(uuid4()): now})
        await self.redis.expire(key, window)
        
        return True, None
```

**Brute Force Protection**:
```python
class BruteForceProtection:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.thresholds = {
            "failed_login": 5,  # Lock after 5 failures
            "lockout_duration": 900  # 15 minutes
        }
        
    async def record_failed_attempt(
        self, identifier: str, attempt_type: str = "login"
    ):
        """Record failed authentication attempt"""
        key = f"failed_attempts:{attempt_type}:{identifier}"
        
        # Increment counter
        count = await self.redis.incr(key)
        
        # Set expiry on first attempt
        if count == 1:
            await self.redis.expire(key, self.thresholds["lockout_duration"])
            
        # Check if should lock
        if count >= self.thresholds["failed_login"]:
            await self.lock_account(identifier)
            
    async def lock_account(self, identifier: str):
        """Lock account/IP after too many failures"""
        key = f"account_locked:{identifier}"
        await self.redis.setex(
            key, 
            self.thresholds["lockout_duration"],
            "locked"
        )
        
        # Log security event
        await log_security_event(
            "account_locked",
            identifier=identifier,
            severity="warning"
        )
        
    async def is_locked(self, identifier: str) -> bool:
        """Check if account/IP is locked"""
        key = f"account_locked:{identifier}"
        return await self.redis.exists(key)
```

**Rate Limit Middleware**:
```python
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    # Get identifier (IP for unauthenticated, user_id for authenticated)
    if hasattr(request.state, "user_id"):
        identifier = request.state.user_id
    else:
        identifier = get_client_ip(request)
        
    # Check rate limit
    allowed, retry_after = await rate_limiter.check_rate_limit(
        identifier, request.url.path
    )
    
    if not allowed:
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded"},
            headers={"Retry-After": str(retry_after)}
        )
        
    # Check brute force lock
    if await brute_force_protection.is_locked(identifier):
        return JSONResponse(
            status_code=423,
            content={"error": "Account temporarily locked"}
        )
        
    return await call_next(request)
```

**Success Criteria**:
- [ ] Rate limiting works
- [ ] Brute force protection
- [ ] Clear error messages
- [ ] Monitoring metrics

### Task 165: Create Auth Flow Documentation
**Priority**: Medium
**Effort**: 0.5 day
**Description**: Comprehensive documentation of authentication flows

**Documentation Structure**:
```
docs/auth/
├── README.md              # Overview
├── quick-start.md         # Getting started
├── architecture.md        # System architecture
├── flows/
│   ├── device-auth.md     # Device authentication
│   ├── token-refresh.md   # Token lifecycle
│   ├── tenant-switch.md   # Multi-tenant
│   └── websocket.md       # WebSocket auth
├── security/
│   ├── threat-model.md    # Security threats
│   ├── best-practices.md  # Security guidelines
│   └── compliance.md      # GDPR/compliance
└── api-reference.md       # API documentation
```

**Flow Diagrams**:
- Device registration sequence
- Login flow with WebAuthn
- Token refresh cycle
- Tenant switching process
- WebSocket authentication

**Security Documentation**:
- No password policy
- Device trust levels
- Rate limiting rules
- Session management
- Audit logging

**Success Criteria**:
- [ ] All flows documented
- [ ] Sequence diagrams
- [ ] Security guidelines
- [ ] API examples

## Testing Requirements

### Performance Tests
- Load test rate limiters
- Concurrent auth requests
- Token validation speed
- Database query performance

### Security Validation
- OWASP Top 10 checklist
- Authentication bypasses
- Authorization flaws
- Session management

### Compliance Tests
- GDPR compliance
- Audit trail completeness
- Data retention policies
- Right to erasure

## Documentation Deliverables
- Complete test reports
- Security assessment
- Performance benchmarks
- Compliance checklist
- Developer guidelines

## Risks & Mitigations
1. **Risk**: Test coverage gaps
   **Mitigation**: Code coverage tools, peer review

2. **Risk**: Security vulnerabilities
   **Mitigation**: External security audit

3. **Risk**: Performance regressions
   **Mitigation**: Benchmark tests in CI

## Definition of Done
- [ ] Unit test coverage >90%
- [ ] Integration tests passing
- [ ] Security tests passing
- [ ] Rate limiting implemented
- [ ] Documentation complete
- [ ] Performance benchmarks met
- [ ] Security review passed
- [ ] No critical vulnerabilities

## Next Sprint Dependencies
This sprint validates:
- All previous auth sprints
- Ready for production
- Security audit ready