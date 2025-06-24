# Sprint 140: User & Tenant Management

## Sprint Goal
Implement user profile management and multi-tenant features including tenant switching, membership validation, and audit logging.

## Duration
Week 7 (5 working days)

## Prerequisites
- Sprint 130 completed (permission system)
- Authentication working
- Tenant context available

## Tasks

### Task 141: Create User Profile Endpoints
**Priority**: High
**Effort**: 1 day
**Description**: Build user profile and preferences API

**Implementation**:
```python
src/api/v1/users/
├── __init__.py
├── router.py
├── schemas.py
├── me_endpoints.py
└── preferences_endpoints.py
```

**API Endpoints**:
```
GET    /api/v1/users/me
       → Current user profile with details
PUT    /api/v1/users/me
       → Update user profile
GET    /api/v1/users/me/preferences
       → User preferences (UI, notifications)
PUT    /api/v1/users/me/preferences
       → Update preferences
DELETE /api/v1/users/me
       → Request account deletion (GDPR)
```

**User Profile Schema**:
```python
class UserProfile(BaseModel):
    id: UUID
    email: str
    display_name: str
    avatar_url: Optional[str]
    external_id: str  # From Authentik
    created_at: datetime
    last_active: datetime
    preferences: UserPreferences
    
class UserPreferences(BaseModel):
    timezone: str = "UTC"
    language: str = "en"
    theme: str = "light"
    notifications: NotificationPreferences
    ai_preferences: AIPreferences
    
class AIPreferences(BaseModel):
    default_llm: Optional[str]
    temperature: float = 0.7
    remember_context: bool = True
    auto_title: bool = True
```

**Success Criteria**:
- [ ] Profile read/update working
- [ ] Preferences persistence
- [ ] Input validation
- [ ] GDPR compliance

### Task 142: Implement Tenant Switching Functionality
**Priority**: Critical
**Effort**: 1.5 days
**Description**: Allow users to switch between tenants they belong to

**Implementation**:
```python
src/api/v1/users/tenant_endpoints.py
src/core/auth/tenant_switcher.py
```

**API Endpoints**:
```
GET  /api/v1/users/me/tenants
     → List user's tenants with roles
POST /api/v1/users/me/tenant/switch
     → Switch active tenant
GET  /api/v1/users/me/tenant/current
     → Get current tenant details
```

**Tenant List Response**:
```python
class UserTenant(BaseModel):
    tenant_id: UUID
    tenant_name: str
    tenant_slug: str
    user_role: str  # admin, member, viewer
    is_active: bool
    joined_at: datetime
    last_accessed: Optional[datetime]
    permissions: List[str]
    
class TenantSwitchRequest(BaseModel):
    tenant_id: UUID
    
class TenantSwitchResponse(BaseModel):
    access_token: str  # New JWT with tenant
    refresh_token: str
    tenant: UserTenant
```

**Switching Logic**:
```python
async def switch_tenant(
    user_id: UUID, 
    target_tenant_id: UUID,
    current_session_id: str
) -> TenantSwitchResponse:
    # Verify user has access to target tenant
    membership = await verify_tenant_membership(user_id, target_tenant_id)
    if not membership:
        raise TenantAccessDeniedError()
    
    # Create new tokens with target tenant
    access_token = create_access_token(
        user_id=user_id,
        tenant_id=target_tenant_id,
        role=membership.role,
        session_id=current_session_id
    )
    
    # Update last accessed
    await update_tenant_last_accessed(user_id, target_tenant_id)
    
    # Audit log
    await log_tenant_switch(user_id, target_tenant_id)
    
    return TenantSwitchResponse(...)
```

**Success Criteria**:
- [ ] List user's tenants
- [ ] Switch tenant securely
- [ ] New tokens issued
- [ ] Audit trail created

### Task 143: Build User-Tenant Membership Validation
**Priority**: Critical
**Effort**: 1 day
**Description**: Validate and manage user-tenant relationships

**Implementation**:
```python
src/core/auth/tenant_membership.py
src/infrastructure/database/models/tenant_member.py
```

**Membership Model**:
```python
class TenantMember(Base):
    __tablename__ = "tenant_members"
    
    id: UUID
    tenant_id: UUID
    user_id: UUID
    role_id: UUID
    invited_by: Optional[UUID]
    invited_at: Optional[datetime]
    joined_at: datetime
    last_accessed: Optional[datetime]
    is_active: bool = True
    
    # Unique constraint
    __table_args__ = (
        UniqueConstraint('tenant_id', 'user_id'),
        Index('idx_member_user', 'user_id'),
        Index('idx_member_tenant', 'tenant_id'),
    )
```

**Validation Functions**:
```python
class TenantMembershipValidator:
    async def validate_membership(
        self, user_id: UUID, tenant_id: UUID
    ) -> Optional[TenantMember]:
        """Check if user is active member of tenant"""
        member = await self.db.query(TenantMember).filter(
            TenantMember.user_id == user_id,
            TenantMember.tenant_id == tenant_id,
            TenantMember.is_active == True
        ).first()
        
        return member
        
    async def validate_role(
        self, user_id: UUID, tenant_id: UUID, required_role: str
    ) -> bool:
        """Check if user has required role in tenant"""
        member = await self.validate_membership(user_id, tenant_id)
        if not member:
            return False
            
        user_role = await self.get_role(member.role_id)
        return user_role.name == required_role or \
               self.is_higher_role(user_role.name, required_role)
```

**Success Criteria**:
- [ ] Membership validation
- [ ] Role hierarchy checks
- [ ] Efficient queries
- [ ] Cache integration

### Task 144: Add User Session Management
**Priority**: High
**Effort**: 1 day
**Description**: Track and manage user sessions across devices

**Implementation**:
```python
src/core/auth/session_manager.py
src/infrastructure/database/models/user_session.py
```

**Session Model**:
```python
class UserSession(Base):
    __tablename__ = "user_sessions"
    
    id: UUID
    user_id: UUID
    tenant_id: UUID
    device_id: Optional[UUID]
    authentik_session_id: str  # Link to Authentik
    ip_address: Optional[str]  # Hashed for privacy
    user_agent: Optional[str]
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    is_active: bool = True
    
class SessionActivity(Base):
    __tablename__ = "session_activities"
    
    id: UUID
    session_id: UUID
    activity_type: str  # api_call, tenant_switch, etc
    timestamp: datetime
    details: Optional[dict]  # JSON
```

**Session Management API**:
```
GET    /api/v1/users/me/sessions
       → List active sessions
DELETE /api/v1/users/me/sessions/{session_id}
       → Terminate specific session
POST   /api/v1/users/me/sessions/terminate-all
       → Terminate all other sessions
```

**Session Features**:
- Track active sessions
- Show device/location info
- Allow session termination
- Sync with Authentik sessions

**Success Criteria**:
- [ ] Session tracking works
- [ ] Can terminate sessions
- [ ] Authentik sync
- [ ] Privacy compliant

### Task 145: Create Audit Logging for Auth Events
**Priority**: High
**Effort**: 0.5 day
**Description**: Comprehensive audit logging for security events

**Implementation**:
```python
src/core/logging/auth_audit.py
src/infrastructure/database/models/audit_log.py
```

**Audit Events**:
```python
class AuthAuditEvent(str, Enum):
    LOGIN_SUCCESS = "auth.login.success"
    LOGIN_FAILED = "auth.login.failed"
    LOGOUT = "auth.logout"
    DEVICE_REGISTERED = "auth.device.registered"
    DEVICE_REMOVED = "auth.device.removed"
    TENANT_SWITCHED = "auth.tenant.switched"
    PERMISSION_GRANTED = "auth.permission.granted"
    PERMISSION_REVOKED = "auth.permission.revoked"
    SESSION_TERMINATED = "auth.session.terminated"
    PROFILE_UPDATED = "user.profile.updated"
    ACCOUNT_DELETION_REQUESTED = "user.deletion.requested"
```

**Audit Log Entry**:
```python
class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id: UUID
    timestamp: datetime
    event_type: str
    user_id: Optional[UUID]
    tenant_id: Optional[UUID]
    ip_address: Optional[str]  # Hashed
    user_agent: Optional[str]
    session_id: Optional[UUID]
    resource_type: Optional[str]
    resource_id: Optional[UUID]
    details: dict  # JSON
    severity: str  # info, warning, critical
    
    # Indexes for querying
    __table_args__ = (
        Index('idx_audit_user', 'user_id', 'timestamp'),
        Index('idx_audit_tenant', 'tenant_id', 'timestamp'),
        Index('idx_audit_event', 'event_type', 'timestamp'),
    )
```

**Audit Logger**:
```python
async def log_auth_event(
    event_type: AuthAuditEvent,
    user_id: Optional[UUID] = None,
    tenant_id: Optional[UUID] = None,
    details: Optional[dict] = None,
    severity: str = "info"
):
    """Log authentication/authorization event"""
    # Get request context
    context = get_request_context()
    
    audit_entry = AuditLog(
        timestamp=datetime.utcnow(),
        event_type=event_type,
        user_id=user_id or context.user_id,
        tenant_id=tenant_id or context.tenant_id,
        ip_address=hash_ip(context.ip_address),
        user_agent=context.user_agent,
        session_id=context.session_id,
        details=details or {},
        severity=severity
    )
    
    await save_audit_log(audit_entry)
```

**Success Criteria**:
- [ ] All auth events logged
- [ ] GDPR compliant (hashed IPs)
- [ ] Queryable audit trail
- [ ] Retention policies

## Testing Requirements

### Unit Tests
- Profile update validation
- Tenant switching logic
- Membership validation
- Session management
- Audit logging

### Integration Tests
- Full tenant switch flow
- Session lifecycle
- Multi-tenant scenarios
- Audit trail generation

### Security Tests
- Tenant isolation in switching
- Session hijacking prevention
- Audit log tampering
- Permission enforcement

## Performance Considerations
- Efficient tenant list queries
- Session query optimization
- Audit log partitioning
- Caching active sessions

## Documentation Deliverables
- User management API docs
- Tenant switching guide
- Session management docs
- Audit log schema
- GDPR compliance notes

## Risks & Mitigations
1. **Risk**: Session sync complexity
   **Mitigation**: Clear Authentik integration docs

2. **Risk**: Audit log volume
   **Mitigation**: Partitioning, retention policies

3. **Risk**: Tenant switch confusion
   **Mitigation**: Clear UI indicators, confirmation

## Definition of Done
- [ ] User profile CRUD working
- [ ] Tenant switching functional
- [ ] Session management complete
- [ ] Audit logging operational
- [ ] GDPR compliance verified
- [ ] Full test coverage
- [ ] Performance acceptable
- [ ] Documentation complete

## Next Sprint Dependencies
This sprint enables:
- Sprint 150: WebSocket authentication
- User-facing features
- Admin dashboards