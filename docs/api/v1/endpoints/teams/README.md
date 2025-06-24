# Teams API

The Teams API provides endpoints for managing teams and team memberships within the nAI Backend platform. Teams enable collaborative workspaces where users can work together on conversations, share resources, and manage agent assignments.

## Overview

- **Base URL**: `/api/v1/teams`
- **Authentication**: Required (JWT Bearer token)
- **Multi-tenant**: Yes (tenant isolation enforced)
- **Rate Limiting**: 
  - Team creation: 5 requests/hour
  - Member management: 20 requests/hour

## Key Features

- **Team Management**: Create, update, and delete teams
- **Member Management**: Add, remove, and update team member roles
- **Role-Based Access**: Owner, Admin, Member, and Viewer roles
- **Tenant Isolation**: Teams are isolated by tenant
- **Audit Logging**: All operations are logged for compliance
- **Real-time Updates**: WebSocket support for team events

## Quick Start

### Create a Team

```bash
curl -X POST https://api.example.com/api/v1/teams \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Engineering Team",
    "slug": "engineering",
    "description": "Backend development team"
  }'
```

### List Your Teams

```bash
curl -X GET https://api.example.com/api/v1/teams \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## Endpoints Summary

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/teams` | Create a new team |
| GET | `/teams` | List user's teams |
| GET | `/teams/{id}` | Get team details |
| PUT | `/teams/{id}` | Update team |
| DELETE | `/teams/{id}` | Delete team |
| POST | `/teams/{id}/members` | Add team member |
| GET | `/teams/{id}/members` | List team members |
| PUT | `/teams/{id}/members/{uid}` | Update member role |
| DELETE | `/teams/{id}/members/{uid}` | Remove team member |

## Team Roles

- **Owner**: Full control, can delete team
- **Admin**: Can manage team and members
- **Member**: Can access team resources
- **Viewer**: Read-only access

## Business Rules

1. **Team Creation**:
   - Subject to tenant team limits
   - Creator automatically becomes owner
   - Slug must be unique within tenant

2. **Member Management**:
   - Only admins/owners can add/remove members
   - Cannot remove the last admin
   - Members must belong to same tenant

3. **Team Deletion**:
   - Only owner can delete team
   - Soft delete (marked as inactive)

## Related Documentation

- [API Reference](./reference.md) - Detailed endpoint documentation
- [Examples](./examples.md) - Code examples in multiple languages
- [Team Management Feature Guide](/docs/features/team-management/README.md)
- [Permissions Guide](/docs/features/team-management/permissions.md)