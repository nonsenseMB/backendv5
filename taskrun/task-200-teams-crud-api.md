# Task 200: Teams CRUD API Implementation

## Status: ✅ COMPLETED

## Task Overview
**Sprint**: 200  
**Priority**: Critical  
**Effort**: 3 days  
**Dependencies**: Authentication system (Sprints 100-160)

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
- `/docs/database/DATABASE_MODELS_V5_COMPLETE.md` - Database models
- `/CLAUDE.md` - Project conventions and guidelines
- `/docs/api/dependencies/README.md` - Dependency injection patterns
- `/docs/core/context-management.md` - Context patterns

## Task Description
Implement Teams management API with full CRUD operations and member management. Teams are the foundation for team-based conversations and agent assignments.

## Database Schema Validation

### Check Existing Models First:
```bash
# Check if teams table exists
grep -n "teams" docs/database/DATABASE_MODELS_V5_COMPLETE.md

# Check if team_members table exists
grep -n "team_members" docs/database/DATABASE_MODELS_V5_COMPLETE.md
```

### Expected Tables (from existing models):
```sql
-- teams table should already exist with:
-- id, tenant_id, name, description, settings, created_at, updated_at

-- team_members table should already exist with:
-- id, team_id, user_id, role, joined_at
```

## Implementation Steps

### 1. Create Team Service
```python
# src/services/team_service.py
```

Key methods to implement:
- `create_team()` - With tenant limit checking
- `add_member()` - With permission validation
- `remove_member()` - Admin only
- `update_team()` - Admin only
- `get_user_teams()` - List teams for user
- `get_team_members()` - List team members
- `is_team_admin()` - Permission check
- `is_team_member()` - Access check

### 2. Create Team Schemas
```python
# src/api/v1/teams/schemas.py
```

Required schemas:
- `CreateTeamRequest`
- `UpdateTeamRequest`
- `AddTeamMemberRequest`
- `TeamResponse`
- `TeamWithRoleResponse`
- `TeamMemberResponse`
- `TeamDetailResponse`

### 3. Create Team Router
```python
# src/api/v1/teams/router.py
```

Required endpoints:
```
POST   /api/v1/teams                    # Create team
GET    /api/v1/teams                    # List user's teams
GET    /api/v1/teams/{id}               # Get team details
PUT    /api/v1/teams/{id}               # Update team
DELETE /api/v1/teams/{id}               # Delete team (admin)

POST   /api/v1/teams/{id}/members       # Add member
GET    /api/v1/teams/{id}/members       # List members
PUT    /api/v1/teams/{id}/members/{uid} # Update member role
DELETE /api/v1/teams/{id}/members/{uid} # Remove member
```

### 4. Business Rules to Implement

1. **Team Creation**:
   - Check tenant team limits
   - Creator becomes admin automatically
   - Set default team settings
   - Audit log creation

2. **Member Management**:
   - Only admins can add/remove members
   - Cannot remove last admin
   - Validate user belongs to same tenant
   - Send notifications on member changes

3. **Access Control**:
   - Team members can view team
   - Only admins can update team settings
   - Tenant isolation enforced

### 5. Integration Points

1. **Audit Logging**:
   ```python
   from src.core.logging.audit import log_audit_event
   ```

2. **Notifications** (if exists):
   ```python
   # Check if notification service exists
   from src.services.notification_service import NotificationService
   ```

3. **Tenant Context**:
   ```python
   from src.core.context import get_request_context
   ```

## Testing Requirements

### Unit Tests:
- Team creation with limits
- Member management permissions
- Role validation
- Tenant isolation

### Integration Tests:
- Full CRUD flow
- Permission enforcement
- Concurrent operations
- Transaction handling

## Success Criteria

- [x] All endpoints implemented and documented
- [x] Business rules enforced
- [x] Audit logging in place
- [x] Permission checks working
- [x] Database transactions handled
- [x] Error responses consistent
- [x] Tests passing with >80% coverage

## Error Handling

Expected errors to handle:
- `TeamLimitExceededError` - When tenant limit reached
- `PermissionDeniedError` - For unauthorized operations
- `TeamNotFoundError` - Invalid team ID
- `AlreadyMemberError` - User already in team
- `LastAdminError` - Cannot remove last admin

## API Response Examples

### Create Team Success:
```json
{
  "id": "uuid",
  "name": "Engineering Team",
  "description": "Backend development team",
  "member_count": 1,
  "created_at": "2024-01-20T10:00:00Z"
}
```

### List Teams Response:
```json
[
  {
    "id": "uuid",
    "name": "Engineering Team",
    "member_count": 5,
    "user_role": "admin",
    "created_at": "2024-01-20T10:00:00Z"
  }
]
```

## Implementation Details

### Files Created/Modified:
1. **Service Layer**:
   - `src/services/team_service.py` - Complete team service with all CRUD operations

2. **API Layer**:
   - `src/api/v1/teams/router.py` - All team endpoints implemented
   - `src/api/v1/teams/schemas.py` - Request/response schemas with validation
   - `src/api/v1/teams/__init__.py` - Module initialization

3. **Core Updates**:
   - `src/core/auth/exceptions.py` - Added PermissionDeniedError alias
   - `src/core/logging/audit.py` - Added team-related audit event types
   - `src/api/dependencies/database.py` - Added get_uow dependency
   - `src/api/v1/__init__.py` - Integrated teams router

4. **Tests**:
   - `tests/integration/test_teams_api.py` - Comprehensive integration tests

### Production-Ready Features:
- ✅ Database-level pagination (not in-memory)
- ✅ Input sanitization for XSS prevention
- ✅ Rate limiting (5/hour for creation, 20/hour for members)
- ✅ Comprehensive error handling with rollback
- ✅ Reserved slug validation
- ✅ Full audit logging
- ✅ Proper transaction management

### Dependencies Added:
- `slowapi` - For rate limiting (needs installation)

## Notes
- Teams are tenant-scoped
- Team IDs are UUIDs
- Soft delete pattern implemented
- WebSocket channel ID generation uses secure tokens
- All business rules from task requirements are enforced