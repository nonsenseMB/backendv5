# Sprint 170: Integration & Performance

## Sprint Goal
Integrate authentication with existing systems, optimize performance, create migration scripts, and conduct final security audit for production readiness.

## Duration
Week 10 (5 working days)

## Prerequisites
- Sprints 100-160 completed
- All tests passing
- Security hardening complete

## Tasks

### Task 171: Integrate Auth with Existing API Endpoints
**Priority**: Critical
**Effort**: 1.5 days
**Description**: Apply authentication to all existing API endpoints

**Implementation**:
```python
src/api/v1/
├── conversations/
│   └── router.py  # Add auth dependencies
├── documents/
│   └── router.py  # Add auth dependencies
├── agents/
│   └── router.py  # Add auth dependencies
├── teams/
│   └── router.py  # Add auth dependencies
└── llm/
    └── router.py  # Add auth dependencies
```

**Endpoint Protection Example**:
```python
# conversations/router.py
from src.api.dependencies.auth import require_auth, get_current_user
from src.api.dependencies.permissions import require_permission

router = APIRouter(
    prefix="/conversations",
    tags=["conversations"],
    dependencies=[Depends(require_auth)]  # Require auth for all endpoints
)

@router.post("/", response_model=ConversationResponse)
async def create_conversation(
    request: CreateConversationRequest,
    user: User = Depends(get_current_user),
    _: None = Depends(require_permission("conversation.create"))
):
    """Create a new conversation"""
    # User and tenant context automatically available
    return await conversation_service.create(
        user_id=user.id,
        tenant_id=user.tenant_id,
        **request.dict()
    )

@router.get("/{conversation_id}", response_model=ConversationResponse)
async def get_conversation(
    conversation_id: UUID,
    user: User = Depends(get_current_user)
):
    """Get conversation by ID"""
    # Service layer handles permission check
    return await conversation_service.get(
        conversation_id=conversation_id,
        user_id=user.id,
        tenant_id=user.tenant_id
    )

@router.delete("/{conversation_id}")
async def delete_conversation(
    conversation_id: UUID,
    user: User = Depends(get_current_user),
    _: None = Depends(require_permission("conversation.delete"))
):
    """Delete a conversation"""
    await conversation_service.delete(
        conversation_id=conversation_id,
        user_id=user.id,
        tenant_id=user.tenant_id
    )
```

**Service Layer Integration**:
```python
# services/conversation_service.py
class ConversationService:
    async def create(
        self,
        user_id: UUID,
        tenant_id: UUID,
        **kwargs
    ) -> Conversation:
        """Create conversation with tenant isolation"""
        conversation = Conversation(
            tenant_id=tenant_id,
            created_by=user_id,
            **kwargs
        )
        
        # Audit log
        await log_audit_event(
            AuditEventType.CONVERSATION_CREATED,
            user_id=user_id,
            tenant_id=tenant_id,
            resource_id=conversation.id
        )
        
        return await self.repository.create(conversation)
        
    async def get(
        self,
        conversation_id: UUID,
        user_id: UUID,
        tenant_id: UUID
    ) -> Conversation:
        """Get conversation with permission check"""
        conversation = await self.repository.get(conversation_id)
        
        # Verify tenant isolation
        if conversation.tenant_id != tenant_id:
            raise TenantAccessDeniedError()
            
        # Check resource permission
        if not await check_resource_permission(
            user_id, "conversation", conversation_id, "read"
        ):
            raise InsufficientPermissionsError()
            
        return conversation
```

**Public Endpoints Configuration**:
```python
# config/public_endpoints.py
PUBLIC_ENDPOINTS = [
    "/api/v1/health",
    "/api/v1/auth/device/register/options",
    "/api/v1/auth/device/login/options",
    "/api/v1/auth/device/login",
    "/api/v1/auth/token/exchange",
    "/docs",
    "/openapi.json"
]
```

**Success Criteria**:
- [ ] All endpoints protected
- [ ] Public endpoints defined
- [ ] Service layer integrated
- [ ] Audit logging added

### Task 172: Add Auth to Database Models and Repositories
**Priority**: Critical
**Effort**: 1 day
**Description**: Integrate authentication context into data layer

**Implementation**:
```python
src/infrastructure/database/
├── base_repository.py  # Add tenant filtering
├── context.py         # Database context
└── repositories/      # Update all repositories
```

**Base Repository with Tenant Filtering**:
```python
# base_repository.py
class TenantAwareRepository(BaseRepository):
    """Base repository with automatic tenant filtering"""
    
    def __init__(self, session: AsyncSession):
        super().__init__(session)
        self._tenant_id = get_current_tenant_id()  # From context
        
    def _apply_tenant_filter(self, query):
        """Apply tenant filter to query"""
        if hasattr(self.model, 'tenant_id'):
            return query.filter(self.model.tenant_id == self._tenant_id)
        return query
        
    async def get(self, id: UUID) -> Optional[Model]:
        """Get by ID with tenant check"""
        query = select(self.model).filter(self.model.id == id)
        query = self._apply_tenant_filter(query)
        result = await self._session.execute(query)
        return result.scalar_one_or_none()
        
    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        **filters
    ) -> List[Model]:
        """List with automatic tenant filtering"""
        query = select(self.model)
        query = self._apply_tenant_filter(query)
        
        # Apply additional filters
        for key, value in filters.items():
            query = query.filter(getattr(self.model, key) == value)
            
        query = query.offset(skip).limit(limit)
        result = await self._session.execute(query)
        return result.scalars().all()
```

**Database Context Manager**:
```python
# context.py
from contextvars import ContextVar

_db_context: ContextVar[dict] = ContextVar('db_context', default={})

def set_db_context(tenant_id: UUID, user_id: UUID):
    """Set database operation context"""
    _db_context.set({
        'tenant_id': tenant_id,
        'user_id': user_id,
        'timestamp': datetime.utcnow()
    })
    
def get_current_tenant_id() -> Optional[UUID]:
    """Get current tenant ID from context"""
    context = _db_context.get()
    return context.get('tenant_id')
    
def get_current_user_id() -> Optional[UUID]:
    """Get current user ID from context"""
    context = _db_context.get()
    return context.get('user_id')
```

**Model Base Class Updates**:
```python
# models/base.py
class TenantAwareModel(Base):
    """Base model with tenant isolation"""
    __abstract__ = True
    
    tenant_id: Mapped[UUID] = mapped_column(
        UUID, nullable=False, index=True
    )
    created_by: Mapped[UUID] = mapped_column(
        UUID, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )
    updated_by: Mapped[Optional[UUID]] = mapped_column(
        UUID, nullable=True
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, onupdate=datetime.utcnow
    )
    
    @declared_attr
    def __table_args__(cls):
        return (
            Index(f'idx_{cls.__tablename__}_tenant', 'tenant_id'),
            Index(f'idx_{cls.__tablename__}_created_by', 'created_by'),
        )
```

**Success Criteria**:
- [ ] Tenant filtering works
- [ ] Context propagation
- [ ] Audit fields populated
- [ ] No data leaks

### Task 173: Implement Auth Caching and Performance Optimization
**Priority**: High
**Effort**: 1 day
**Description**: Optimize authentication performance with caching

**Implementation**:
```python
src/infrastructure/cache/
├── auth_cache.py
├── permission_cache.py
└── session_cache.py
```

**Multi-Level Caching Strategy**:
```python
# auth_cache.py
class AuthCache:
    def __init__(self, redis_client, local_cache_size=1000):
        self.redis = redis_client
        self.local_cache = LRUCache(maxsize=local_cache_size)
        self.ttl = {
            'user': 300,  # 5 minutes
            'permissions': 300,  # 5 minutes
            'jwks': 3600,  # 1 hour
            'session': 900  # 15 minutes
        }
        
    async def get_user(self, user_id: UUID) -> Optional[User]:
        """Get user with two-level caching"""
        # Check local cache first
        cache_key = f"user:{user_id}"
        user = self.local_cache.get(cache_key)
        if user:
            return user
            
        # Check Redis
        user_data = await self.redis.get(cache_key)
        if user_data:
            user = User.parse_raw(user_data)
            self.local_cache[cache_key] = user
            return user
            
        return None
        
    async def set_user(self, user: User):
        """Cache user in both levels"""
        cache_key = f"user:{user.id}"
        
        # Local cache
        self.local_cache[cache_key] = user
        
        # Redis cache
        await self.redis.setex(
            cache_key,
            self.ttl['user'],
            user.json()
        )
```

**Permission Cache with Warming**:
```python
# permission_cache.py
class PermissionCache:
    async def warm_cache(self, user_id: UUID, tenant_id: UUID):
        """Pre-load user permissions"""
        # Get all user roles
        roles = await get_user_roles(user_id, tenant_id)
        
        # Calculate effective permissions
        permissions = set()
        for role in roles:
            permissions.update(role.permissions)
            
        # Cache the result
        await self.set_permissions(user_id, tenant_id, permissions)
        
    async def get_permissions(
        self, user_id: UUID, tenant_id: UUID
    ) -> Set[str]:
        """Get cached permissions with fallback"""
        cache_key = f"perms:{tenant_id}:{user_id}"
        
        # Try cache
        cached = await self.redis.get(cache_key)
        if cached:
            return set(json.loads(cached))
            
        # Cache miss - calculate and cache
        permissions = await self.calculate_permissions(user_id, tenant_id)
        await self.set_permissions(user_id, tenant_id, permissions)
        
        return permissions
```

**Performance Optimizations**:
```python
# JWT Validation Optimization
class OptimizedJWTValidator:
    def __init__(self):
        self.jwks_cache = TTLCache(maxsize=10, ttl=3600)
        self.validated_tokens = TTLCache(maxsize=10000, ttl=300)
        
    async def validate_token(self, token: str) -> dict:
        """Validate with caching"""
        # Check if recently validated
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        if token_hash in self.validated_tokens:
            return self.validated_tokens[token_hash]
            
        # Validate token
        payload = await self._validate_jwt(token)
        
        # Cache result
        self.validated_tokens[token_hash] = payload
        
        return payload
```

**Database Query Optimization**:
```python
# Optimized permission queries
async def get_user_permissions_optimized(
    user_id: UUID, tenant_id: UUID
) -> List[str]:
    """Get permissions with single query"""
    query = text("""
        WITH user_roles AS (
            SELECT r.id, r.name
            FROM roles r
            JOIN user_roles ur ON ur.role_id = r.id
            WHERE ur.user_id = :user_id
            AND ur.tenant_id = :tenant_id
        )
        SELECT DISTINCT p.name
        FROM permissions p
        JOIN role_permissions rp ON rp.permission_id = p.id
        JOIN user_roles ur ON ur.id = rp.role_id
        ORDER BY p.name
    """)
    
    result = await db.execute(
        query,
        {"user_id": user_id, "tenant_id": tenant_id}
    )
    
    return [row[0] for row in result]
```

**Success Criteria**:
- [ ] JWT validation <10ms
- [ ] Permission check <5ms
- [ ] Cache hit rate >90%
- [ ] Memory usage stable

### Task 174: Create Migration Scripts for Existing Data
**Priority**: High
**Effort**: 1 day
**Description**: Migrate existing data to support authentication

**Migration Scripts**:
```python
migrations/auth/
├── 001_add_auth_tables.py
├── 002_add_tenant_columns.py
├── 003_migrate_existing_users.py
├── 004_create_default_roles.py
└── 005_assign_user_roles.py
```

**Add Tenant Columns Migration**:
```python
# 002_add_tenant_columns.py
"""Add tenant_id to existing tables"""

def upgrade():
    # Add tenant_id to tables
    tables_to_update = [
        'conversations',
        'documents',
        'agents',
        'teams',
        'knowledge_graphs'
    ]
    
    for table in tables_to_update:
        op.add_column(
            table,
            sa.Column('tenant_id', sa.UUID(), nullable=True)
        )
        
        # Add created_by if missing
        op.add_column(
            table,
            sa.Column('created_by', sa.UUID(), nullable=True)
        )
        
    # Create indexes
    for table in tables_to_update:
        op.create_index(
            f'idx_{table}_tenant',
            table,
            ['tenant_id']
        )

def downgrade():
    # Remove columns and indexes
    pass
```

**Migrate Existing Users**:
```python
# 003_migrate_existing_users.py
"""Migrate existing users to auth system"""

def upgrade():
    # Create default tenant
    op.execute("""
        INSERT INTO tenants (id, name, slug, created_at)
        VALUES (
            '00000000-0000-0000-0000-000000000001',
            'Default Tenant',
            'default',
            NOW()
        )
    """)
    
    # Migrate users
    op.execute("""
        INSERT INTO users (id, external_id, email, tenant_id, created_at)
        SELECT 
            id,
            id::text,  -- Use existing ID as external_id
            email,
            '00000000-0000-0000-0000-000000000001',
            created_at
        FROM old_users
    """)
    
    # Update foreign keys
    op.execute("""
        UPDATE conversations 
        SET tenant_id = '00000000-0000-0000-0000-000000000001'
        WHERE tenant_id IS NULL
    """)
```

**Create Default Roles**:
```python
# 004_create_default_roles.py
"""Create system roles and permissions"""

def upgrade():
    # Create permissions
    permissions = [
        ('tenant.manage', 'tenant', 'manage', 'Manage tenant settings'),
        ('user.manage', 'user', 'manage', 'Manage users'),
        ('conversation.create', 'conversation', 'create', 'Create conversations'),
        ('conversation.read', 'conversation', 'read', 'Read conversations'),
        ('conversation.update', 'conversation', 'update', 'Update conversations'),
        ('conversation.delete', 'conversation', 'delete', 'Delete conversations'),
        # ... more permissions
    ]
    
    for name, resource, action, description in permissions:
        op.execute(f"""
            INSERT INTO permissions (id, name, resource, action, description)
            VALUES (gen_random_uuid(), '{name}', '{resource}', '{action}', '{description}')
        """)
    
    # Create system roles
    roles = [
        ('admin', True, ['tenant.manage', 'user.manage', 'conversation.*']),
        ('member', True, ['conversation.create', 'conversation.read']),
        ('viewer', True, ['conversation.read', 'document.read'])
    ]
    
    for role_name, is_system, perms in roles:
        role_id = str(uuid4())
        op.execute(f"""
            INSERT INTO roles (id, name, tenant_id, is_system)
            VALUES ('{role_id}', '{role_name}', NULL, {is_system})
        """)
        
        # Assign permissions
        for perm in perms:
            if perm.endswith('*'):
                # Wildcard - assign all permissions for resource
                op.execute(f"""
                    INSERT INTO role_permissions (role_id, permission_id)
                    SELECT '{role_id}', id FROM permissions
                    WHERE resource = '{perm[:-2]}'
                """)
            else:
                op.execute(f"""
                    INSERT INTO role_permissions (role_id, permission_id)
                    SELECT '{role_id}', id FROM permissions
                    WHERE name = '{perm}'
                """)
```

**Data Validation Script**:
```python
# validate_migration.py
async def validate_migration():
    """Validate data after migration"""
    
    print("Validating migration...")
    
    # Check all tables have tenant_id
    tables = ['conversations', 'documents', 'users']
    for table in tables:
        count = await db.execute(
            f"SELECT COUNT(*) FROM {table} WHERE tenant_id IS NULL"
        )
        if count.scalar() > 0:
            print(f"❌ {table} has records without tenant_id")
        else:
            print(f"✅ {table} fully migrated")
            
    # Check user roles
    users_without_roles = await db.execute("""
        SELECT COUNT(*) FROM users u
        LEFT JOIN user_roles ur ON u.id = ur.user_id
        WHERE ur.id IS NULL
    """)
    
    if users_without_roles.scalar() > 0:
        print("❌ Some users don't have roles")
    else:
        print("✅ All users have roles")
```

**Success Criteria**:
- [ ] Migration scripts tested
- [ ] Rollback scripts work
- [ ] Data integrity maintained
- [ ] No data loss

### Task 175: Final Security Audit and Compliance Check
**Priority**: Critical
**Effort**: 0.5 day
**Description**: Conduct final security review and compliance validation

**Security Checklist**:
```python
# security_audit.py
async def run_security_audit():
    """Comprehensive security audit"""
    
    results = []
    
    # 1. Check for password fields
    print("Checking for password fields...")
    password_fields = await check_password_fields()
    results.append(("No password fields", len(password_fields) == 0))
    
    # 2. Verify device auth required
    print("Checking device auth configuration...")
    device_auth = os.getenv("DEVICE_AUTH_REQUIRED") == "true"
    results.append(("Device auth required", device_auth))
    
    # 3. Check JWT configuration
    print("Checking JWT security...")
    jwt_secure = (
        os.getenv("JWT_ALGORITHM") == "RS256" and
        os.getenv("JWT_ISSUER") is not None
    )
    results.append(("JWT properly configured", jwt_secure))
    
    # 4. Verify tenant isolation
    print("Testing tenant isolation...")
    isolation_test = await test_tenant_isolation()
    results.append(("Tenant isolation working", isolation_test))
    
    # 5. Check audit logging
    print("Verifying audit logs...")
    audit_test = await test_audit_logging()
    results.append(("Audit logging complete", audit_test))
    
    # Print results
    print("\n=== Security Audit Results ===")
    for check, passed in results:
        status = "✅" if passed else "❌"
        print(f"{status} {check}")
```

**Compliance Validation**:
```python
# compliance_check.py
async def validate_gdpr_compliance():
    """Validate GDPR compliance"""
    
    checks = []
    
    # Right to access
    can_export = await test_user_data_export()
    checks.append(("User data export", can_export))
    
    # Right to erasure
    can_delete = await test_user_deletion()
    checks.append(("User deletion", can_delete))
    
    # Data minimization
    no_excess_data = await check_data_minimization()
    checks.append(("Data minimization", no_excess_data))
    
    # Audit trail
    has_audit_trail = await check_audit_trail_completeness()
    checks.append(("Complete audit trail", has_audit_trail))
    
    return all(check[1] for check in checks)
```

**Production Readiness Checklist**:
- [ ] All tests passing
- [ ] Security audit clean
- [ ] Performance benchmarks met
- [ ] Documentation complete
- [ ] Migration tested
- [ ] Monitoring configured
- [ ] Backup strategy defined
- [ ] Incident response plan

**Success Criteria**:
- [ ] Security audit passed
- [ ] GDPR compliant
- [ ] Performance acceptable
- [ ] Production ready

## Testing Requirements

### Performance Benchmarks
- Auth check: <10ms p99
- Permission lookup: <5ms p99
- Token validation: <10ms p99
- Concurrent users: 10,000+

### Load Testing
- 1000 concurrent logins
- 10,000 active sessions
- 100,000 permission checks/sec
- WebSocket: 5000 connections

### Final Integration Tests
- End-to-end user journey
- Multi-tenant scenarios
- Permission edge cases
- Migration validation

## Documentation Deliverables
- Production deployment guide
- Performance tuning guide
- Security best practices
- Migration runbook
- Monitoring setup

## Risks & Mitigations
1. **Risk**: Migration data loss
   **Mitigation**: Backup, dry run, validation

2. **Risk**: Performance degradation
   **Mitigation**: Caching, optimization, monitoring

3. **Risk**: Security vulnerabilities
   **Mitigation**: External audit, penetration testing

## Definition of Done
- [ ] All endpoints integrated
- [ ] Database layer secured
- [ ] Performance optimized
- [ ] Migration complete
- [ ] Security audit passed
- [ ] Compliance verified
- [ ] Documentation complete
- [ ] Production ready

## Post-Sprint Actions
1. Schedule external security audit
2. Plan production deployment
3. Set up monitoring/alerting
4. Create runbooks
5. Train operations team