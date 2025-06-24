# JWT Authentication Middleware

## Overview

The JWT authentication middleware provides token-based authentication for all API endpoints. It extracts and validates JWT tokens issued by Authentik, sets user context for request processing, and handles token expiration gracefully.

## Features

- **Bearer Token Extraction**: Supports Authorization header and cookie-based tokens
- **JWKS-based Validation**: Validates tokens against Authentik's public keys
- **Public Endpoint Bypass**: Configurable list of endpoints that don't require auth
- **Token Expiration Handling**: Provides refresh token flow for expired access tokens
- **Request Context**: Sets user_id, tenant_id, session_id, and permissions in request state
- **Security Headers**: Automatically adds security headers to responses

## Configuration

### Public Endpoints

Configure endpoints that don't require authentication in `src/api/middleware/auth.py`:

```python
PUBLIC_ENDPOINTS = {
    "/",
    "/health",
    "/health/simple",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/api/v1/auth/token",
    "/api/v1/auth/refresh",
    "/api/v1/auth/callback",
    "/api/v1/auth/device/register",
    "/api/v1/auth/device/verify",
}

PUBLIC_ENDPOINT_PATTERNS = [
    re.compile(r"^/api/v1/auth/.*$"),  # All auth endpoints
    re.compile(r"^/static/.*$"),       # Static files
    re.compile(r"^/_health/.*$"),      # Health check variants
]
```

## Usage

### Client Request Format

Send JWT token in Authorization header:

```bash
curl -H "Authorization: Bearer <jwt-token>" \
     https://api.example.com/api/v1/protected
```

Or use cookies:

```bash
curl -b "access_token=<jwt-token>" \
     https://api.example.com/api/v1/protected
```

### Response Headers

The middleware adds security headers to all authenticated responses:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`

### Error Responses

#### Missing Token

```json
{
    "error": "unauthorized",
    "message": "Missing authentication token",
    "detail": "Bearer token required in Authorization header"
}
```

#### Expired Token

```json
{
    "error": "token_expired",
    "message": "Access token has expired",
    "detail": "Token has expired",
    "tokens": {
        "access_token": "new-access-token",
        "refresh_token": "new-refresh-token",
        "token_type": "Bearer",
        "expires_in": 900
    }
}
```

#### Invalid Token

```json
{
    "error": "invalid_token",
    "message": "Invalid authentication token",
    "detail": "Token signature verification failed"
}
```

## Request State

After successful authentication, the following attributes are available in `request.state`:

- `user_id`: The user's unique identifier (sub claim)
- `tenant_id`: The tenant identifier
- `session_id`: The Authentik session ID
- `permissions`: List of user permissions
- `groups`: List of user groups
- `token_claims`: Full decoded token claims

## FastAPI Dependencies

Use the provided dependencies for endpoint protection:

```python
from fastapi import Depends
from src.api.dependencies.auth import get_current_user, require_auth

@app.get("/api/v1/users/me")
async def get_me(user = Depends(get_current_user)):
    return {"user_id": user.id, "email": user.email}

@app.get("/api/v1/protected")
async def protected_endpoint(user_id: str = Depends(require_auth)):
    return {"message": f"Hello user {user_id}"}
```

## Token Refresh Flow

When an access token expires:

1. Client receives 401 with `error: "token_expired"`
2. Response includes new tokens if refresh token is valid
3. Client should update stored tokens and retry request

Example refresh handling:

```javascript
async function apiCall(url, options = {}) {
    const response = await fetch(url, {
        ...options,
        headers: {
            ...options.headers,
            'Authorization': `Bearer ${getAccessToken()}`
        }
    });
    
    if (response.status === 401) {
        const data = await response.json();
        if (data.error === 'token_expired' && data.tokens) {
            // Update stored tokens
            setAccessToken(data.tokens.access_token);
            setRefreshToken(data.tokens.refresh_token);
            
            // Retry request with new token
            return apiCall(url, options);
        }
    }
    
    return response;
}
```

## Security Considerations

1. **HTTPS Required**: Always use HTTPS in production
2. **Token Storage**: Store tokens securely (httpOnly cookies preferred)
3. **Token Expiration**: Access tokens expire in 15 minutes by default
4. **CORS Configuration**: Configure CORS appropriately for your frontend
5. **Rate Limiting**: Implement rate limiting on authentication endpoints

## Troubleshooting

### Token Not Found

- Check Authorization header format: `Bearer <token>`
- Verify cookie name matches configuration
- Ensure token hasn't expired

### Validation Failures

- Check Authentik is accessible from backend
- Verify JWKS endpoint is configured correctly
- Ensure clock sync between servers (NTP)

### Performance Issues

- JWKS cache TTL is 1 hour by default
- Token validation is done on every request
- Consider implementing a short-lived token cache

## See Also

- [Authentik Integration Architecture](../../architecture/authentik-integration.md)
- [Token Exchange Service](../services/token-exchange.md)
- [FastAPI Dependencies](../dependencies/auth.md)