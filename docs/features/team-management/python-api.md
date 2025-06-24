# Team Management Python API

This guide covers the Python API for team management in the nAI Backend.

## TeamService

The `TeamService` class provides all team management functionality.

### Initialization

```python
from src.services.team_service import TeamService
from src.infrastructure.database.unit_of_work import UnitOfWork

# Initialize with Unit of Work
uow = UnitOfWork(session, tenant_id)
team_service = TeamService(uow)
```

## Core Methods

### create_team

Create a new team within the tenant.

```python
async def create_team(
    self,
    name: str,
    slug: str,
    created_by: UUID,
    description: Optional[str] = None,
    avatar_url: Optional[str] = None,
    settings: Optional[dict] = None
) -> Team:
```

**Example:**

```python
team = await team_service.create_team(
    name="Data Science Team",
    slug="data-science",
    created_by=user_id,
    description="ML and data analysis team",
    settings={
        "notifications": True,
        "auto_share_conversations": True,
        "default_share_permission": "write"
    }
)
```

**Exceptions:**
- `TeamLimitExceededError`: Tenant team limit reached
- `ValueError`: Invalid slug or slug already taken
- `TeamError`: General team operation error

### add_member

Add a new member to an existing team.

```python
async def add_member(
    self,
    team_id: UUID,
    user_id: UUID,
    role: str = 'member',
    invited_by: Optional[UUID] = None,
    permissions: Optional[list[str]] = None
) -> TeamMember:
```

**Example:**

```python
member = await team_service.add_member(
    team_id=team.id,
    user_id=new_user_id,
    role='admin',
    invited_by=current_user_id,
    permissions=['manage_integrations']
)
```

**Exceptions:**
- `TeamNotFoundError`: Team doesn't exist
- `PermissionDeniedError`: User lacks permission
- `AlreadyMemberError`: User already in team
- `ValueError`: User not in tenant

### remove_member

Remove a member from the team.

```python
async def remove_member(
    self,
    team_id: UUID,
    user_id: UUID,
    removed_by: UUID
) -> bool:
```

**Example:**

```python
success = await team_service.remove_member(
    team_id=team.id,
    user_id=member_id,
    removed_by=admin_id
)
```

**Exceptions:**
- `TeamNotFoundError`: Team doesn't exist
- `PermissionDeniedError`: User lacks permission
- `LastAdminError`: Cannot remove last admin

### update_team

Update team information.

```python
async def update_team(
    self,
    team_id: UUID,
    updated_by: UUID,
    name: Optional[str] = None,
    description: Optional[str] = None,
    avatar_url: Optional[str] = None,
    settings: Optional[dict] = None
) -> Team:
```

**Example:**

```python
team = await team_service.update_team(
    team_id=team.id,
    updated_by=admin_id,
    name="Engineering & DevOps",
    settings={"notifications": False}
)
```

### get_user_teams

Get all teams a user belongs to.

```python
async def get_user_teams(
    self,
    user_id: UUID,
    only_active: bool = True
) -> list[Team]:
```

**Example:**

```python
teams = await team_service.get_user_teams(
    user_id=current_user_id,
    only_active=True
)
```

### get_user_teams_paginated

Get paginated teams for better performance.

```python
async def get_user_teams_paginated(
    self,
    user_id: UUID,
    only_active: bool = True,
    skip: int = 0,
    limit: int = 20
) -> list[Team]:
```

### count_user_teams

Count teams a user belongs to.

```python
async def count_user_teams(
    self,
    user_id: UUID,
    only_active: bool = True
) -> int:
```

### get_team_members

Get members of a team.

```python
async def get_team_members(
    self,
    team_id: UUID,
    only_active: bool = True,
    skip: int = 0,
    limit: int = 100
) -> list[TeamMember]:
```

**Example:**

```python
members = await team_service.get_team_members(
    team_id=team.id,
    only_active=True,
    skip=0,
    limit=50
)
```

### update_member_role

Update a member's role in the team.

```python
async def update_member_role(
    self,
    team_id: UUID,
    user_id: UUID,
    new_role: str,
    updated_by: UUID,
    permissions: Optional[list[str]] = None
) -> TeamMember:
```

**Example:**

```python
member = await team_service.update_member_role(
    team_id=team.id,
    user_id=member_id,
    new_role='admin',
    updated_by=owner_id,
    permissions=['manage_integrations', 'manage_agents']
)
```

### delete_team

Soft delete a team (owner only).

```python
async def delete_team(
    self,
    team_id: UUID,
    deleted_by: UUID
) -> bool:
```

## Permission Check Methods

### is_team_admin

Check if user is admin or owner.

```python
async def is_team_admin(
    self,
    team_id: UUID,
    user_id: UUID
) -> bool:
```

### is_team_member

Check if user is a team member.

```python
async def is_team_member(
    self,
    team_id: UUID,
    user_id: UUID
) -> bool:
```

## Error Handling

```python
from src.services.team_service import (
    TeamError,
    TeamLimitExceededError,
    TeamNotFoundError,
    AlreadyMemberError,
    LastAdminError
)

try:
    team = await team_service.create_team(...)
except TeamLimitExceededError:
    # Handle team limit
    pass
except ValueError as e:
    # Handle validation errors
    pass
except TeamError as e:
    # Handle general team errors
    pass
```

## Complete Example

```python
from uuid import UUID
from src.services.team_service import TeamService
from src.infrastructure.database.unit_of_work import UnitOfWork

async def setup_team(uow: UnitOfWork, owner_id: UUID):
    service = TeamService(uow)
    
    # Create team
    team = await service.create_team(
        name="Product Team",
        slug="product",
        created_by=owner_id,
        description="Product development team"
    )
    
    # Add members
    for user_id in team_member_ids:
        try:
            await service.add_member(
                team_id=team.id,
                user_id=user_id,
                role='member',
                invited_by=owner_id
            )
        except AlreadyMemberError:
            continue
    
    # Promote someone to admin
    await service.update_member_role(
        team_id=team.id,
        user_id=admin_user_id,
        new_role='admin',
        updated_by=owner_id
    )
    
    return team
```

## Best Practices

1. **Always use try-except blocks** for team operations
2. **Check permissions** before operations
3. **Use pagination** for large member lists
4. **Validate slugs** before creation
5. **Log important operations** for audit trail
6. **Handle race conditions** in member operations

## Related Documentation

- [Team Management Overview](./README.md)
- [Permissions Guide](./permissions.md)
- [REST API Reference](/docs/api/v1/endpoints/teams/reference.md)