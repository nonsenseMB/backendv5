# Sprint 130: Permission & Authorization System

## Sprint Goal
Build a comprehensive role-based and resource-based permission system with tenant-scoped authorization for fine-grained access control.

## Duration
Week 6 (5 working days)

## Prerequisites
- Sprint 110 completed (middleware & dependencies)
- User authentication working
- Tenant context available

## Tasks

### Task 131: Define Permission Model and Roles
**Priority**: Critical
**Effort**: 1 day
**Description**: Design and implement the permission model with roles

**Implementation**:
```python
src/core/auth/permissions.py
src/infrastructure/database/models/permission.py
```

**Permission Model**:
```python
class Permission(Base):
    __tablename__ = "permissions"
    
    id: UUID
    name: str  # e.g., "conversation.create"
    resource: str  # e.g., "conversation"
    action: str  # e.g., "create"
    description: str
    
class Role(Base):
    __tablename__ = "roles"
    
    id: UUID
    name: str  # Admin, Member, Viewer
    tenant_id: UUID  # Tenant-specific roles
    permissions: List[Permission]  # Many-to-many
    is_system: bool = False  # System vs custom roles
    
class UserRole(Base):
    __tablename__ = "user_roles"
    
    user_id: UUID
    role_id: UUID
    tenant_id: UUID
    granted_by: UUID
    granted_at: datetime
```

**System Roles**:
```python
SYSTEM_ROLES = {
    "admin": [
        "tenant.manage",
        "user.manage",
        "conversation.*",
        "document.*",
        "agent.*",
        "tool.*",
        "memory.*"
    ],
    "member": [
        "conversation.create",
        "conversation.read",
        "conversation.update",
        "document.create",
        "document.read",
        "agent.use",
        "memory.read"
    ],
    "viewer": [
        "conversation.read",
        "document.read",
        "memory.read"
    ]
}
```

**Success Criteria**:
- [ ] Permission model defined
- [ ] System roles created
- [ ] Database migrations
- [ ] Role assignment API

### Task 132: Implement Permission Checking Middleware
**Priority**: Critical
**Effort**: 1 day
**Description**: Create middleware for permission validation

**Implementation**:
```python
src/api/middleware/permissions.py
src/core/auth/permission_checker.py
```

**Permission Checking Flow**:
```python
class PermissionMiddleware:
    async def __call__(self, request: Request, call_next):
        # Extract required permission from route
        permission = get_route_permission(request)
        
        if permission:
            user_id = request.state.user_id
            tenant_id = request.state.tenant_id
            
            if not await check_permission(user_id, tenant_id, permission):
                raise HTTPException(403, "Insufficient permissions")
                
        return await call_next(request)
```

**Route Permission Mapping**:
```python
ROUTE_PERMISSIONS = {
    ("POST", "/api/v1/conversations"): "conversation.create",
    ("GET", "/api/v1/conversations/{id}"): "conversation.read",
    ("PUT", "/api/v1/conversations/{id}"): "conversation.update",
    ("DELETE", "/api/v1/conversations/{id}"): "conversation.delete",
}
```

**Success Criteria**:
- [ ] Automatic permission checks
- [ ] Clear error messages
- [ ] Performance optimized
- [ ] Bypass for public routes

### Task 133: Create Resource-Level Permission System
**Priority**: High
**Effort**: 1.5 days
**Description**: Implement fine-grained resource permissions

**Implementation**:
```python
src/core/auth/resource_permissions.py
src/infrastructure/database/models/resource_permission.py
```

**Resource Permission Model**:
```python
class ResourcePermission(Base):
    __tablename__ = "resource_permissions"
    
    id: UUID
    resource_type: str  # "document", "conversation"
    resource_id: UUID
    user_id: Optional[UUID]  # User-specific
    team_id: Optional[UUID]  # Team-specific
    permission: str  # "read", "write", "delete"
    granted_by: UUID
    granted_at: datetime
    expires_at: Optional[datetime]
    
    # Unique constraint
    __table_args__ = (
        UniqueConstraint(
            'resource_type', 'resource_id', 
            'user_id', 'team_id', 'permission'
        ),
    )
```

**Permission Check Function**:
```python
async def check_resource_permission(
    user_id: UUID,
    resource_type: str,
    resource_id: UUID,
    permission: str,
    tenant_id: UUID
) -> bool:
    # Check role-based permission first
    if await has_role_permission(user_id, f"{resource_type}.{permission}"):
        return True
        
    # Check resource-specific permission
    return await has_resource_permission(
        user_id, resource_type, resource_id, permission
    )
```

**Success Criteria**:
- [ ] Resource permissions work
- [ ] Team-based permissions
- [ ] Permission inheritance
- [ ] Expiring permissions

### Task 134: Build Tenant-Scoped Permission Validation
**Priority**: Critical
**Effort**: 1 day
**Description**: Ensure all permissions are tenant-isolated

**Implementation**:
```python
src/core/auth/tenant_permissions.py
```

**Tenant Isolation Rules**:
1. Users can only have roles within their tenants
2. Resources belong to exactly one tenant
3. Cross-tenant access is never allowed
4. System admins have no cross-tenant access

**Validation Logic**:
```python
class TenantPermissionValidator:
    async def validate_tenant_access(
        self,
        user_id: UUID,
        tenant_id: UUID,
        resource_type: Optional[str] = None,
        resource_id: Optional[UUID] = None
    ) -> bool:
        # Verify user belongs to tenant
        if not await user_belongs_to_tenant(user_id, tenant_id):
            return False
            
        # Verify resource belongs to tenant (if provided)
        if resource_type and resource_id:
            if not await resource_belongs_to_tenant(
                resource_type, resource_id, tenant_id
            ):
                return False
                
        return True
```

**Database Query Filter**:
```python
def apply_tenant_filter(query, tenant_id: UUID):
    """Apply tenant filter to SQLAlchemy query"""
    return query.filter(Model.tenant_id == tenant_id)
```

**Success Criteria**:
- [ ] Tenant isolation enforced
- [ ] No cross-tenant leaks
- [ ] Query filters applied
- [ ] Clear audit trail

### Task 135: Add Permission Caching Layer
**Priority**: Medium
**Effort**: 0.5 day
**Description**: Cache permissions for performance

**Implementation**:
```python
src/infrastructure/cache/permission_cache.py
```

**Caching Strategy**:
```python
class PermissionCache:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.ttl = 300  # 5 minutes
        
    async def get_user_permissions(
        self, user_id: UUID, tenant_id: UUID
    ) -> Optional[Set[str]]:
        key = f"perms:{tenant_id}:{user_id}"
        cached = await self.redis.get(key)
        if cached:
            return set(json.loads(cached))
        return None
        
    async def set_user_permissions(
        self, user_id: UUID, tenant_id: UUID, permissions: Set[str]
    ):
        key = f"perms:{tenant_id}:{user_id}"
        await self.redis.setex(
            key, self.ttl, json.dumps(list(permissions))
        )
        
    async def invalidate_user_permissions(
        self, user_id: UUID, tenant_id: UUID
    ):
        key = f"perms:{tenant_id}:{user_id}"
        await self.redis.delete(key)
```

**Cache Invalidation**:
- On role assignment/removal
- On resource permission change
- On user status change
- Periodic refresh (5 min TTL)

**Success Criteria**:
- [ ] Permission caching works
- [ ] Cache invalidation correct
- [ ] Performance improvement
- [ ] Cache metrics tracked

## Testing Requirements

### Unit Tests
- Permission calculation logic
- Role inheritance
- Resource permission checks
- Cache behavior

### Integration Tests
- End-to-end permission flow
- Tenant isolation
- Role assignment
- Permission changes

### Security Tests
- Permission bypass attempts
- Tenant isolation violations
- Privilege escalation
- Cache poisoning

## Performance Considerations
- Efficient permission queries
- Batch permission checks
- Cache warming strategies
- Index optimization

## API Endpoints

```
# Role Management
GET    /api/v1/roles                    # List available roles
POST   /api/v1/users/{user_id}/roles    # Assign role
DELETE /api/v1/users/{user_id}/roles/{role_id}  # Remove role

# Resource Permissions
POST   /api/v1/permissions/resource     # Grant resource permission
DELETE /api/v1/permissions/resource     # Revoke resource permission
GET    /api/v1/permissions/check        # Check specific permission

# User Permissions
GET    /api/v1/users/me/permissions     # List my permissions
GET    /api/v1/users/{user_id}/permissions  # List user permissions (admin)
```

## Documentation Deliverables
- Permission model diagram
- Role hierarchy documentation
- Resource permission guide
- API endpoint documentation
- Best practices guide

## Risks & Mitigations
1. **Risk**: Complex permission calculations
   **Mitigation**: Aggressive caching, clear logic

2. **Risk**: Permission sprawl
   **Mitigation**: Well-defined permission taxonomy

3. **Risk**: Performance impact
   **Mitigation**: Caching, optimized queries

## Definition of Done
- [ ] Permission model implemented
- [ ] System roles working
- [ ] Resource permissions functional
- [ ] Tenant isolation verified
- [ ] Caching layer operational
- [ ] Full test coverage
- [ ] Performance benchmarks met
- [ ] Documentation complete

## Next Sprint Dependencies
This sprint enables:
- Sprint 140: User management features
- All business logic requiring permissions
- Admin interfaces