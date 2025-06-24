# Teams API Reference

## Create Team

Create a new team. The creator automatically becomes the team owner.

**Endpoint**: `POST /api/v1/teams`

**Rate Limit**: 5 requests/hour

### Request

```http
POST /api/v1/teams
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Engineering Team",
  "slug": "engineering",
  "description": "Backend development team",
  "avatar_url": "https://example.com/team-avatar.png",
  "settings": {
    "notifications": true,
    "auto_share_conversations": false,
    "default_share_permission": "read"
  }
}
```

### Request Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Team name (1-255 chars) |
| slug | string | Yes | URL-friendly identifier (lowercase, alphanumeric + hyphens) |
| description | string | No | Team description (max 1000 chars) |
| avatar_url | string | No | Team avatar URL |
| settings | object | No | Team settings |

**Settings Object**:
- `notifications` (boolean): Enable team notifications
- `auto_share_conversations` (boolean): Auto-share new conversations
- `default_share_permission` (string): "read" or "write"

### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440001",
  "name": "Engineering Team",
  "slug": "engineering",
  "description": "Backend development team",
  "avatar_url": "https://example.com/team-avatar.png",
  "member_count": 1,
  "is_active": true,
  "created_at": "2024-01-20T10:30:00Z",
  "updated_at": "2024-01-20T10:30:00Z"
}
```

### Error Responses

- `400 Bad Request`: Invalid input or slug already taken
- `403 Forbidden`: Team limit exceeded
- `409 Conflict`: Slug already exists

---

## List Teams

Get all teams the authenticated user is a member of.

**Endpoint**: `GET /api/v1/teams`

### Request

```http
GET /api/v1/teams?page=1&page_size=20&only_active=true
Authorization: Bearer <token>
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | integer | 1 | Page number (min: 1) |
| page_size | integer | 20 | Items per page (1-100) |
| only_active | boolean | true | Include only active teams |

### Response

```json
{
  "teams": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "name": "Engineering Team",
      "slug": "engineering",
      "description": "Backend development team",
      "avatar_url": null,
      "member_count": 5,
      "is_active": true,
      "created_at": "2024-01-20T10:30:00Z",
      "updated_at": "2024-01-20T10:30:00Z",
      "user_role": "owner"
    }
  ],
  "total": 3,
  "page": 1,
  "page_size": 20
}
```

---

## Get Team Details

Get detailed information about a specific team.

**Endpoint**: `GET /api/v1/teams/{team_id}`

### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440001",
  "name": "Engineering Team",
  "slug": "engineering",
  "description": "Backend development team",
  "avatar_url": null,
  "member_count": 5,
  "is_active": true,
  "created_at": "2024-01-20T10:30:00Z",
  "updated_at": "2024-01-20T10:30:00Z",
  "settings": {
    "notifications": true,
    "auto_share_conversations": false,
    "default_share_permission": "read"
  },
  "team_agent_id": null,
  "ws_channel_id": "team-550e8400-e29b-41d4-a716-446655440001-abc123",
  "active_conversations": 12,
  "created_by": "550e8400-e29b-41d4-a716-446655440002",
  "creator": {
    "id": "550e8400-e29b-41d4-a716-446655440002",
    "email": "john@example.com",
    "username": "johndoe",
    "full_name": "John Doe",
    "avatar_url": null
  },
  "metadata": {}
}
```

### Error Responses

- `403 Forbidden`: Not a team member
- `404 Not Found`: Team not found

---

## Update Team

Update team information. Only admins can update teams.

**Endpoint**: `PUT /api/v1/teams/{team_id}`

### Request

```json
{
  "name": "Backend Engineering",
  "description": "Core backend development team",
  "avatar_url": "https://example.com/new-avatar.png",
  "settings": {
    "notifications": false
  }
}
```

### Request Schema

All fields are optional. Only provided fields will be updated.

| Field | Type | Description |
|-------|------|-------------|
| name | string | Team name (1-255 chars) |
| description | string | Team description (max 1000 chars) |
| avatar_url | string | Team avatar URL |
| settings | object | Team settings (merged with existing) |

### Error Responses

- `403 Forbidden`: Not an admin
- `404 Not Found`: Team not found

---

## Delete Team

Soft delete a team. Only the team owner can delete a team.

**Endpoint**: `DELETE /api/v1/teams/{team_id}`

### Response

```http
HTTP/1.1 204 No Content
```

### Error Responses

- `403 Forbidden`: Not the team owner
- `404 Not Found`: Team not found

---

## Add Team Member

Add a new member to the team. Only admins can add members.

**Endpoint**: `POST /api/v1/teams/{team_id}/members`

**Rate Limit**: 20 requests/hour

### Request

```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440003",
  "role": "member",
  "permissions": []
}
```

### Request Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| user_id | uuid | Yes | User ID to add |
| role | string | No | Role: owner, admin, member, viewer (default: member) |
| permissions | array | No | Additional permissions |

### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440004",
  "user_id": "550e8400-e29b-41d4-a716-446655440003",
  "team_id": "550e8400-e29b-41d4-a716-446655440001",
  "role": "member",
  "permissions": [],
  "is_active": true,
  "joined_at": "2024-01-20T11:00:00Z",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440003",
    "email": "jane@example.com",
    "username": "janedoe",
    "full_name": "Jane Doe",
    "avatar_url": null
  }
}
```

### Error Responses

- `400 Bad Request`: User not found or not in tenant
- `403 Forbidden`: Not an admin
- `404 Not Found`: Team not found
- `409 Conflict`: User already a member

---

## List Team Members

Get all members of a team.

**Endpoint**: `GET /api/v1/teams/{team_id}/members`

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| only_active | boolean | true | Include only active members |
| skip | integer | 0 | Number of items to skip |
| limit | integer | 100 | Maximum items to return (1-500) |

### Response

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440004",
    "user_id": "550e8400-e29b-41d4-a716-446655440002",
    "team_id": "550e8400-e29b-41d4-a716-446655440001",
    "role": "owner",
    "permissions": [],
    "is_active": true,
    "joined_at": "2024-01-20T10:30:00Z",
    "user": {
      "id": "550e8400-e29b-41d4-a716-446655440002",
      "email": "john@example.com",
      "username": "johndoe",
      "full_name": "John Doe",
      "avatar_url": null
    }
  }
]
```

### Error Responses

- `403 Forbidden`: Not a team member
- `404 Not Found`: Team not found

---

## Update Member Role

Update a team member's role. Only admins can update roles.

**Endpoint**: `PUT /api/v1/teams/{team_id}/members/{user_id}`

### Request

```json
{
  "role": "admin",
  "permissions": ["manage_integrations"]
}
```

### Request Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| role | string | Yes | New role: owner, admin, member, viewer |
| permissions | array | No | Additional permissions |

### Error Responses

- `400 Bad Request`: Invalid role or user not a member
- `403 Forbidden`: Not an admin
- `404 Not Found`: Team not found
- `409 Conflict`: Cannot demote last admin

---

## Remove Team Member

Remove a member from the team. Admins can remove any member, members can remove themselves.

**Endpoint**: `DELETE /api/v1/teams/{team_id}/members/{user_id}`

### Response

```http
HTTP/1.1 204 No Content
```

### Error Responses

- `403 Forbidden`: Not authorized
- `404 Not Found`: Team or member not found
- `409 Conflict`: Cannot remove last admin

---

## Common Error Response Format

```json
{
  "detail": "Error message describing what went wrong"
}
```

## Security Notes

1. **XSS Prevention**: All text fields (name, description) are HTML-escaped
2. **Reserved Slugs**: System slugs (admin, api, system, etc.) cannot be used
3. **Tenant Isolation**: All operations are scoped to the authenticated user's tenant
4. **Rate Limiting**: Enforced per IP address to prevent abuse