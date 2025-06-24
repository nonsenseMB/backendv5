# API v1 Endpoints

This directory contains documentation for all API v1 endpoints organized by feature area.

## Available Endpoints

### [Authentication](./auth/)
- User authentication and authorization
- Token management
- Device trust
- Session management

### [Health](./health/)
- System health checks
- Readiness probes
- Liveness probes

### [Teams](./teams/) ⭐ NEW
- Team CRUD operations
- Member management
- Role-based permissions
- Collaborative workspaces

## Base URL

All endpoints are prefixed with `/api/v1`.

Example: `https://api.example.com/api/v1/teams`

## Authentication

Most endpoints require authentication via JWT Bearer token:

```http
Authorization: Bearer <token>
```

## Common Response Formats

### Success Response
```json
{
  "data": {...},
  "message": "Success"
}
```

### Error Response
```json
{
  "detail": "Error message"
}
```

## Rate Limiting

Different endpoints have different rate limits. Check individual endpoint documentation for specific limits.

## Pagination

List endpoints support pagination with query parameters:
- `page` - Page number (default: 1)
- `page_size` - Items per page (default: 20, max: 100)

## Related Documentation

- [API Reference](/docs/api/API_REFERENCE.md)
- [Authentication Guide](/docs/features/authentication/README.md)
- [OpenAPI Specification](/docs/api/openapi.yaml)