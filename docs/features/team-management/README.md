# Team Management

Team management is a core feature of the nAI Backend that enables collaborative workspaces where multiple users can work together on AI conversations, share resources, and manage agent assignments.

## Overview

Teams provide:
- **Collaborative Workspaces**: Share conversations and resources
- **Role-Based Access Control**: Fine-grained permissions
- **Tenant Isolation**: Complete data separation
- **Real-time Updates**: WebSocket support for live collaboration
- **Audit Trail**: Compliance-ready activity logging

## Quick Start

### Creating Your First Team

```python
from src.services.team_service import TeamService
from src.infrastructure.database.unit_of_work import UnitOfWork

async def create_team(uow: UnitOfWork):
    service = TeamService(uow)
    
    team = await service.create_team(
        name="Engineering Team",
        slug="engineering",
        created_by=user_id,
        description="Backend development team"
    )
    
    return team
```

### Adding Team Members

```python
member = await service.add_member(
    team_id=team.id,
    user_id=new_user_id,
    role="member",
    invited_by=admin_id
)
```

## Team Roles

### Owner
- Full control over the team
- Can delete the team
- Can transfer ownership
- All admin permissions

### Admin
- Manage team settings
- Add/remove members
- Update member roles
- Cannot delete team

### Member
- Access team resources
- Participate in conversations
- View other members

### Viewer
- Read-only access
- Cannot modify resources
- Cannot invite others

## Key Features

### 1. Team Creation Limits

Teams are subject to tenant plan limits:
- Trial: 1 team
- Starter: 3 teams
- Professional: 10 teams
- Enterprise: Unlimited

### 2. Member Management

- **Invitation System**: Admins invite users by ID
- **Auto-join**: Users must be in same tenant
- **Role Changes**: Admins can promote/demote
- **Self-removal**: Members can leave teams

### 3. Security Features

- **Tenant Isolation**: Teams cannot access other tenant data
- **Permission Checks**: All operations validate permissions
- **Audit Logging**: All actions are logged
- **Soft Delete**: Teams are marked inactive, not deleted

### 4. WebSocket Integration

Each team gets a unique WebSocket channel for real-time updates:
- Member additions/removals
- Role changes
- Team updates
- Shared conversation events

## Business Rules

1. **Last Admin Protection**: Cannot remove or demote the last admin
2. **Owner Privileges**: Only owner can delete team or transfer ownership
3. **Tenant Membership**: All members must belong to same tenant
4. **Unique Slugs**: Team slugs must be unique within tenant
5. **Reserved Slugs**: System slugs (admin, api, etc.) are prohibited

## Configuration

Teams use the following settings:

```python
{
    "notifications": True,           # Enable team notifications
    "auto_share_conversations": False,  # Auto-share new conversations
    "default_share_permission": "read"  # Default permission for shares
}
```

## Performance Considerations

- **Pagination**: Use database-level pagination for large teams
- **Caching**: Consider caching membership checks
- **Indexes**: Ensure proper indexes on team_id, user_id
- **Batch Operations**: Use bulk operations for multiple members

## Related Documentation

- [Python API Reference](./python-api.md)
- [Permissions Guide](./permissions.md)
- [Configuration Options](./configuration.md)
- [Troubleshooting Guide](./troubleshooting.md)
- [API Endpoints](/docs/api/v1/endpoints/teams/README.md)