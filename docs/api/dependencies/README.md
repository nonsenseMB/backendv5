# FastAPI Dependencies Documentation

This document describes the FastAPI dependencies available for authentication, authorization, and context management in the nAI Backend v5.

## Overview

The dependency system provides reusable components for:
- **Authentication**: User extraction and validation
- **Authorization**: Permission and role-based access control
- **Tenant Management**: Multi-tenant context and isolation
- **Session Management**: Session validation and metadata

## Authentication Dependencies (`src/api/dependencies/auth.py`)

### `get_current_user_id`
Extracts the authenticated user's ID from the request state.

```python
from src.api.dependencies.auth import get_current_user_id

@router.get("/example")
async def example(user_id: UUID = Depends(get_current_user_id)):
    return {"user_id": str(user_id)}
```

### `get_current_user`
Retrieves the full user object from the database.

```python
from src.api.dependencies.auth import get_current_user

@router.get("/profile")
async def get_profile(user: User = Depends(get_current_user)):
    return {"email": user.email, "name": user.full_name}
```

### `get_optional_user`
Returns the user if authenticated, otherwise None. Useful for endpoints that support both authenticated and anonymous access.

```python
@router.get("/public")
async def public_endpoint(user: Optional[User] = Depends(get_optional_user)):
    if user:
        return {"message": f"Hello {user.email}"}
    return {"message": "Hello anonymous"}
```

### `require_auth`
Simple dependency that ensures authentication and returns the user ID.

```python
@router.post("/protected")
async def protected_endpoint(user_id: UUID = Depends(require_auth)):
    return {"message": "Access granted", "user_id": str(user_id)}
```

### `get_current_active_user`
Ensures the user is both authenticated and active.

### `get_current_verified_user`
Ensures the user has verified their email address.

## Tenant Dependencies (`src/api/dependencies/tenant.py`)

### `get_current_tenant`
Retrieves the current tenant from the database.

```python
from src.api.dependencies.tenant import get_current_tenant

@router.get("/tenant-info")
async def tenant_info(tenant: Tenant = Depends(get_current_tenant)):
    return {"name": tenant.name, "plan": tenant.plan_type}
```

### `get_tenant_user`
Gets the TenantUser association, providing role and permission information.

```python
@router.get("/my-role")
async def get_my_role(tenant_user: TenantUser = Depends(get_tenant_user)):
    return {"role": tenant_user.role, "permissions": tenant_user.permissions}
```

### `require_tenant_role`
Creates a dependency that requires a specific tenant role.

```python
@router.delete("/admin-action")
async def admin_only(
    _: TenantUser = Depends(require_tenant_role("admin"))
):
    return {"message": "Admin action performed"}
```

Role hierarchy:
- `owner` > `admin` > `member` > `viewer`

### `ensure_tenant_context`
Ensures tenant context is set for the request.

## Permission Dependencies (`src/api/dependencies/permissions.py`)

### `require_permission`
Requires a specific permission.

```python
from src.api.dependencies.permissions import require_permission

@router.get("/users")
async def list_users(
    _: User = Depends(require_permission("users:read"))
):
    return {"users": []}
```

### `require_any_permission`
Requires at least one of the specified permissions.

```python
@router.post("/create")
async def create_item(
    _: User = Depends(require_any_permission(["items:write", "admin"]))
):
    return {"created": True}
```

### `require_all_permissions`
Requires all of the specified permissions.

```python
@router.delete("/sensitive")
async def sensitive_action(
    _: User = Depends(require_all_permissions(["sensitive:read", "sensitive:write"]))
):
    return {"success": True}
```

### `require_tenant_permission`
Checks permissions within the tenant context, combining JWT permissions with tenant-specific permissions.

```python
@router.post("/tenant-resource")
async def create_tenant_resource(
    _: TenantUser = Depends(require_tenant_permission("resources:create"))
):
    return {"created": True}
```

### Permission Format
Permissions follow the format `resource:action`, for example:
- `users:read`
- `users:write`
- `teams:manage`
- `billing:view`

Wildcard permissions are supported:
- `users:*` grants all user permissions
- `admin` or `superuser` grants all permissions

## Session Dependencies (`src/api/dependencies/session.py`)

### `get_current_session`
Retrieves and validates the current session.

```python
from src.api.dependencies.session import get_current_session

@router.get("/session-info")
async def session_info(session: SessionInfo = Depends(get_current_session)):
    return {
        "session_id": str(session.session_id),
        "created_at": session.created_at.isoformat()
    }
```

### `get_session_metadata`
Returns session metadata as a dictionary.

```python
@router.get("/debug/session")
async def debug_session(metadata: dict = Depends(get_session_metadata)):
    return metadata
```

### `invalidate_current_session`
Invalidates the current session (useful for logout).

```python
@router.post("/logout")
async def logout(success: bool = Depends(invalidate_current_session)):
    return {"logged_out": success}
```

## Combining Dependencies

Dependencies can be combined for complex authorization requirements:

```python
@router.post("/complex-endpoint")
async def complex_endpoint(
    user: User = Depends(get_current_active_user),
    tenant: Tenant = Depends(get_current_tenant),
    tenant_user: TenantUser = Depends(require_tenant_role("admin")),
    _: User = Depends(require_permission("advanced:feature")),
    session: SessionInfo = Depends(get_current_session),
):
    # This endpoint requires:
    # 1. An active authenticated user
    # 2. A valid tenant context
    # 3. Admin role in the tenant
    # 4. The 'advanced:feature' permission
    # 5. A valid session
    
    return {
        "user_id": str(user.id),
        "tenant_id": str(tenant.id),
        "role": tenant_user.role,
        "session_id": str(session.session_id)
    }
```

## Custom Dependencies

You can create custom dependencies by combining existing ones:

```python
def require_premium_tenant():
    """Dependency that requires a premium tenant plan."""
    async def check_premium(
        tenant: Tenant = Depends(get_current_tenant),
    ):
        if tenant.plan_type not in ["professional", "enterprise"]:
            raise HTTPException(
                status_code=403,
                detail="Premium plan required"
            )
        return tenant
    return check_premium

@router.get("/premium-feature")
async def premium_feature(
    tenant: Tenant = Depends(require_premium_tenant())
):
    return {"plan": tenant.plan_type}
```

## Error Responses

The dependencies return consistent error responses:

- **401 Unauthorized**: Missing or invalid authentication
- **403 Forbidden**: Insufficient permissions or inactive resources
- **404 Not Found**: Resource not found (e.g., tenant)

Example error response:
```json
{
    "detail": "Permission 'users:write' required"
}
```

## Best Practices

1. **Use the most specific dependency**: If you only need the user ID, use `require_auth` instead of `get_current_user`

2. **Combine dependencies logically**: Group related checks together

3. **Document required permissions**: Make it clear what permissions/roles are needed

4. **Handle optional auth gracefully**: Use `get_optional_user` for public endpoints that enhance functionality for authenticated users

5. **Test dependencies thoroughly**: Ensure all authorization paths are tested

## Integration with Middleware

These dependencies work seamlessly with the JWT validation middleware that:
- Extracts tokens from headers/cookies
- Validates JWT signatures
- Sets request state with user context
- Handles token refresh

The middleware runs before dependencies, ensuring the request state is properly populated.