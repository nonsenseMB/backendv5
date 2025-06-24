# Task 207: Basic Tenant Settings API

## Task Overview
**Sprint**: 200  
**Priority**: Medium  
**Effort**: 2 days  
**Dependencies**: 
- Authentication system complete
- Tenant structure exists

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
- `/docs/database/DATABASE_MODELS_V5_COMPLETE.md` - Tenant models
- `/docs/features/authentication/README.md` - Auth patterns
- Existing tenant implementation

## Task Description
Implement basic tenant management APIs that allow users to view tenant information, usage statistics, and admins to update tenant settings.

## Database Schema Validation

### 1. Check Existing Tenant Tables:
```bash
# Check tenant structure
grep -A 30 "tenants" docs/database/DATABASE_MODELS_V5_COMPLETE.md

# Check tenant_users relationship
grep -A 10 "tenant_users" docs/database/DATABASE_MODELS_V5_COMPLETE.md
```

### 2. Expected Schema:
```sql
-- tenants table should have:
-- id, name, settings, limits, created_at, updated_at

-- tenant_users should have:
-- tenant_id, user_id, role, joined_at
```

### 3. Additional Fields Needed:
```sql
-- Add if not exists
ALTER TABLE tenants 
ADD COLUMN IF NOT EXISTS subscription_tier VARCHAR(50) DEFAULT 'free',
ADD COLUMN IF NOT EXISTS max_users INTEGER DEFAULT 10,
ADD COLUMN IF NOT EXISTS max_teams INTEGER DEFAULT 5,
ADD COLUMN IF NOT EXISTS max_conversations INTEGER DEFAULT 100,
ADD COLUMN IF NOT EXISTS max_tokens_per_month INTEGER DEFAULT 1000000;
```

## Implementation Components

### 1. Tenant Settings Service
```python
# src/services/tenant_settings_service.py
```

Key methods:
- `get_tenant_info()` - Get tenant details with user role
- `update_tenant_settings()` - Admin-only settings update
- `get_usage_stats()` - Current usage metrics
- `get_tenant_limits()` - Subscription limits
- `validate_settings()` - Validate setting changes

### 2. Usage Tracking Service
```python
# src/services/tenant_usage_service.py
```

Track and calculate:
- Active users count
- Teams created
- Conversations count
- Tokens used this month
- Storage used
- API calls made

Usage calculation queries:
```python
# Users count
SELECT COUNT(DISTINCT user_id) 
FROM tenant_users 
WHERE tenant_id = :tenant_id

# Monthly tokens
SELECT SUM(total_tokens) 
FROM conversations 
WHERE tenant_id = :tenant_id 
AND created_at >= DATE_TRUNC('month', CURRENT_DATE)
```

### 3. Tenant API Router
```python
# src/api/v1/tenants/router.py
```

Endpoints:
```
GET    /api/v1/tenants/current         # Get current tenant info
GET    /api/v1/tenants/current/usage   # Get usage statistics
PUT    /api/v1/tenants/current/settings # Update settings (admin)
GET    /api/v1/tenants/current/limits  # Get subscription limits
```

### 4. Request/Response Schemas
```python
# src/api/v1/tenants/schemas.py
```

Schemas needed:
```python
class TenantInfoResponse(BaseModel):
    id: UUID
    name: str
    subscription_tier: str
    created_at: datetime
    user_role: str  # admin, member, viewer
    member_count: int
    
class TenantUsageResponse(BaseModel):
    users_count: int
    users_limit: int
    teams_count: int
    teams_limit: int
    conversations_count: int
    conversations_limit: int
    tokens_used: int
    tokens_limit: int
    storage_used_mb: float
    api_calls_today: int
    
class UpdateTenantSettingsRequest(BaseModel):
    name: Optional[str]
    settings: Optional[Dict[str, Any]]
    
class TenantSettingsResponse(BaseModel):
    settings: Dict[str, Any]
    updated_at: datetime
```

## Business Rules

### 1. Access Control:
- All authenticated users can view tenant info
- Only tenant admins can update settings
- Usage stats visible to all members
- Sensitive settings hidden from non-admins

### 2. Setting Validation:
- Name length: 3-100 characters
- Settings size limit: 10KB
- Restricted setting keys for security
- Audit log all changes

### 3. Usage Limits:
- Enforce based on subscription tier
- Grace period for overages
- Email notifications at 80%, 90%, 100%
- Block operations at hard limits

## Tenant Settings Structure

### Default Settings:
```json
{
  "branding": {
    "primary_color": "#000000",
    "logo_url": null
  },
  "notifications": {
    "email_enabled": true,
    "webhook_url": null
  },
  "security": {
    "ip_whitelist": [],
    "mfa_required": false,
    "session_timeout_minutes": 60
  },
  "features": {
    "custom_models_enabled": false,
    "api_access_enabled": true,
    "sso_enabled": false
  },
  "integrations": {
    "slack_workspace": null,
    "microsoft_teams": null
  }
}
```

### Subscription Tiers:
```python
SUBSCRIPTION_LIMITS = {
    "free": {
        "max_users": 5,
        "max_teams": 2,
        "max_conversations": 50,
        "max_tokens_per_month": 100000,
        "features": ["basic_chat", "team_collaboration"]
    },
    "starter": {
        "max_users": 20,
        "max_teams": 10,
        "max_conversations": 500,
        "max_tokens_per_month": 1000000,
        "features": ["basic_chat", "team_collaboration", "api_access"]
    },
    "business": {
        "max_users": 100,
        "max_teams": 50,
        "max_conversations": 5000,
        "max_tokens_per_month": 10000000,
        "features": ["all"]
    },
    "enterprise": {
        "max_users": -1,  # Unlimited
        "max_teams": -1,
        "max_conversations": -1,
        "max_tokens_per_month": -1,
        "features": ["all", "custom_deployment", "sla"]
    }
}
```

## Caching Strategy

### 1. Cache Tenant Info:
```python
# Cache key: tenant:info:{tenant_id}
# TTL: 5 minutes
# Invalidate on: settings update
```

### 2. Cache Usage Stats:
```python
# Cache key: tenant:usage:{tenant_id}
# TTL: 1 minute
# Update strategy: Write-through
```

## Testing Requirements

### Unit Tests:
- Settings validation
- Usage calculations
- Permission checks
- Limit enforcement

### Integration Tests:
- Full update flow
- Cache invalidation
- Concurrent updates
- Rate limiting

### Test Scenarios:
1. Admin updates settings
2. Non-admin tries update (should fail)
3. Usage near limits
4. Invalid settings rejected
5. Concurrent usage updates

## Monitoring & Metrics

### Track:
- API response times
- Cache hit rates
- Setting update frequency
- Usage query performance
- Limit violations

### Alerts:
- High API latency
- Failed updates
- Approaching limits
- Unusual usage patterns

## Success Criteria

- [ ] All endpoints implemented
- [ ] Permission checks working
- [ ] Usage calculations accurate
- [ ] Settings validation robust
- [ ] Caching improves performance
- [ ] Audit logging complete
- [ ] Tests passing >80% coverage
- [ ] Documentation updated

## Error Handling

Expected errors:
- `TenantNotFoundError`
- `PermissionDeniedError`  
- `InvalidSettingsError`
- `UsageLimitExceededError`
- `ConcurrentUpdateError`

## Migration Notes

For existing tenants:
1. Add default settings
2. Calculate initial usage
3. Set appropriate limits
4. Notify admins of new features

## Security Considerations

1. **Settings Validation**:
   - Sanitize all inputs
   - Prevent script injection
   - Validate URLs
   - Check file sizes

2. **Rate Limiting**:
   - 10 updates per hour per tenant
   - 100 reads per minute
   - Block suspicious activity

3. **Audit Trail**:
   - Log all setting changes
   - Track who made changes
   - Store previous values
   - Retention per compliance

## Future Enhancements

Consider for later:
1. Settings history/rollback
2. Setting templates
3. Bulk tenant management
4. Usage forecasting
5. Cost estimation
6. Custom limits negotiation