# Authentik Token Exchange Architecture

**Version**: 4.0.0
**Last Updated**: 2025-06-22
**Author**: Mike Berndt <berndt.mike@gmail.com>

## Overview

The nAI Backend v4 implements a token exchange mechanism that allows clients authenticated via Authentik OAuth2 to exchange their Authentik tokens for backend JWT tokens. This enables seamless integration between Authentik as the identity provider and the backend's internal JWT-based authentication system.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Token Exchange Flow](#token-exchange-flow)
3. [Implementation Details](#implementation-details)
4. [API Endpoints](#api-endpoints)
5. [Security Considerations](#security-considerations)
6. [Frontend Integration](#frontend-integration)
7. [Troubleshooting](#troubleshooting)

## Architecture Overview

```mermaid
graph TB
    subgraph "Frontend Application"
        CLIENT[Web/Mobile Client]
    end

    subgraph "Identity Provider"
        AUTHENTIK[Authentik OAuth2 Server]
    end

    subgraph "Backend API"
        EXCHANGE[Token Exchange Endpoint]
        JWT_SERVICE[JWT Service]
        USER_SERVICE[User Service]
        API[Protected API Endpoints]
    end

    subgraph "Storage"
        DB[(PostgreSQL)]
        REDIS[(Redis Cache)]
    end

    CLIENT -->|1. OAuth2 Login| AUTHENTIK
    AUTHENTIK -->|2. Authentik Token| CLIENT
    CLIENT -->|3. Exchange Request| EXCHANGE
    EXCHANGE -->|4. Validate Token| AUTHENTIK
    EXCHANGE -->|5. Get/Create User| USER_SERVICE
    USER_SERVICE --> DB
    EXCHANGE -->|6. Create JWT| JWT_SERVICE
    JWT_SERVICE --> REDIS
    EXCHANGE -->|7. Backend JWT| CLIENT
    CLIENT -->|8. API Calls with JWT| API
```

## Token Exchange Flow

### Complete Authentication Flow

```mermaid
sequenceDiagram
    participant User
    participant Frontend
    participant Authentik
    participant Backend
    participant Database

    %% OAuth2 Login Flow
    User->>Frontend: Click Login
    Frontend->>Authentik: Redirect to OAuth2 Login
    User->>Authentik: Enter Credentials
    Authentik->>User: Redirect with Auth Code
    User->>Frontend: Return with Code
    Frontend->>Authentik: Exchange Code for Token
    Authentik-->>Frontend: Authentik Access Token

    %% Token Exchange Flow
    Frontend->>Backend: POST /api/v1/auth/exchange
    Note right of Frontend: {authentik_token, tenant_slug}

    Backend->>Authentik: GET /application/o/userinfo/
    Note right of Backend: Validate Token
    Authentik-->>Backend: User Information

    Backend->>Database: Find or Create User
    Database-->>Backend: User Record

    Backend->>Backend: Generate JWT Tokens
    Backend-->>Frontend: Backend JWT Tokens
    Note left of Backend: {access_token, refresh_token}

    %% API Usage
    Frontend->>Backend: GET /api/v1/conversations
    Note right of Frontend: Authorization: Bearer {jwt}
    Backend->>Backend: Validate JWT
    Backend-->>Frontend: API Response
```

### Token Refresh Flow

```mermaid
sequenceDiagram
    participant Frontend
    participant Backend
    participant Database

    Frontend->>Backend: POST /api/v1/auth/refresh
    Note right of Frontend: {refresh_token}

    Backend->>Backend: Validate Refresh Token
    Backend->>Database: Get User
    Database-->>Backend: User Record

    Backend->>Backend: Generate New Tokens
    Backend-->>Frontend: New Token Pair
    Note left of Backend: {access_token, refresh_token}
```

## Implementation Details

### Token Exchange Endpoint

**Endpoint**: `POST /api/v1/auth/exchange`

**Purpose**: Exchange an Authentik OAuth2 token for backend JWT tokens

**Request**:

```json
{
  "authentik_token": "string",
  "tenant_slug": "string" // Optional, defaults to "default"
}
```

**Response**:

```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "username": "johndoe",
    "full_name": "John Doe",
    "groups": ["users", "developers"],
    "permissions": ["read", "write"],
    "tenant": {
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "slug": "default",
      "name": "Default Organization"
    }
  }
}
```

### Token Validation Process

1. **Authentik Token Validation**:
   - Backend calls Authentik's userinfo endpoint
   - Validates token authenticity
   - Retrieves user information

2. **User Management**:
   - Searches for existing user by email
   - Creates new user if not found
   - Updates user information from Authentik
   - Associates user with tenant

3. **JWT Generation**:
   - Creates access token (1 hour validity)
   - Creates refresh token (30 days validity)
   - Includes user context and permissions

### Token Refresh Endpoint

**Endpoint**: `POST /api/v1/auth/refresh`

**Purpose**: Refresh an expired access token using a refresh token

**Request**:

```json
{
  "refresh_token": "string"
}
```

**Response**: Same as token exchange response

## API Endpoints

### Public Endpoints (No Authentication Required)

- `POST /api/v1/auth/exchange` - Exchange Authentik token for backend JWT
- `POST /api/v1/auth/refresh` - Refresh access token
- `GET /api/v1/health` - Health check
- `GET /api/v1/docs` - API documentation

### Protected Endpoints (JWT Required)

All other endpoints require a valid backend JWT token in the Authorization header:

```http
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...
```

## Security Considerations

### Token Security

1. **Token Storage**:
   - Access tokens: Store in memory or sessionStorage
   - Refresh tokens: Store in httpOnly cookies or secure storage
   - Never store tokens in localStorage for production

2. **Token Transmission**:
   - Always use HTTPS in production
   - Include tokens only in Authorization headers
   - Never include tokens in URL parameters

3. **Token Validation**:
   - Verify token signature using RS256
   - Check token expiration
   - Validate issuer and audience claims
   - Verify user is still active

### Rate Limiting

- Token exchange: 10 requests per minute per IP
- Token refresh: 20 requests per minute per user
- Failed attempts: 5 attempts before temporary lockout

### Security Headers

The backend automatically adds security headers to all responses:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`

## Frontend Integration

### JavaScript/TypeScript Example

```typescript
class AuthService {
  private accessToken: string | null = null;
  private refreshToken: string | null = null;

  // Exchange Authentik token for backend tokens
  async exchangeToken(authentikToken: string): Promise<void> {
    const response = await fetch('/api/v1/auth/exchange', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        authentik_token: authentikToken,
        tenant_slug: 'default'
      }),
    });

    if (!response.ok) {
      throw new Error('Token exchange failed');
    }

    const data = await response.json();
    this.accessToken = data.access_token;
    this.refreshToken = data.refresh_token;

    // Store user information
    localStorage.setItem('user', JSON.stringify(data.user));
  }

  // Make authenticated API call
  async apiCall(endpoint: string, options: RequestInit = {}): Promise<Response> {
    const response = await fetch(endpoint, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${this.accessToken}`,
      },
    });

    // If 401, try to refresh token
    if (response.status === 401 && this.refreshToken) {
      await this.refreshAccessToken();
      // Retry the request
      return fetch(endpoint, {
        ...options,
        headers: {
          ...options.headers,
          'Authorization': `Bearer ${this.accessToken}`,
        },
      });
    }

    return response;
  }

  // Refresh access token
  async refreshAccessToken(): Promise<void> {
    const response = await fetch('/api/v1/auth/refresh', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        refresh_token: this.refreshToken
      }),
    });

    if (!response.ok) {
      // Refresh failed, need to re-authenticate
      this.logout();
      throw new Error('Session expired');
    }

    const data = await response.json();
    this.accessToken = data.access_token;
    this.refreshToken = data.refresh_token;
  }

  logout(): void {
    this.accessToken = null;
    this.refreshToken = null;
    localStorage.removeItem('user');
    // Redirect to login
    window.location.href = '/login';
  }
}
```

### React Integration Example

```jsx
import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

function AuthCallback() {
  const [searchParams] = useSearchParams();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function handleCallback() {
      const code = searchParams.get('code');
      if (!code) {
        setError('No authorization code received');
        return;
      }

      try {
        // Exchange code for Authentik token
        const tokenResponse = await fetch('https://authentik.example.com/application/o/token/', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: window.location.origin + '/callback',
            client_id: 'your-client-id',
            code_verifier: sessionStorage.getItem('code_verifier'),
          }),
        });

        const { access_token } = await tokenResponse.json();

        // Exchange Authentik token for backend token
        const authService = new AuthService();
        await authService.exchangeToken(access_token);

        // Redirect to dashboard
        window.location.href = '/dashboard';
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }

    handleCallback();
  }, [searchParams]);

  if (loading) return <div>Authenticating...</div>;
  if (error) return <div>Error: {error}</div>;
  return null;
}
```

## Troubleshooting

### Common Issues

1. **400 Bad Request on Token Exchange**
   - Verify Authentik token is valid
   - Check token hasn't expired
   - Ensure correct Content-Type header

2. **401 Unauthorized on API Calls**
   - Verify JWT token is included in Authorization header
   - Check token expiration
   - Ensure user is active in database

3. **502 Bad Gateway on Token Exchange**
   - Check Authentik server is accessible
   - Verify AUTHENTIK_PUBLIC_URL configuration
   - Check network connectivity

4. **Token Refresh Fails**
   - Ensure refresh token hasn't expired (30 days)
   - Verify refresh token is valid
   - Check user still exists and is active

### Debug Mode

Enable debug logging for authentication:

```python
# Set in environment
LOG_LEVEL=DEBUG

# Or in code
import logging
logging.getLogger("src.api.v1.auth.token_exchange").setLevel(logging.DEBUG)
```

### Health Check

Verify token exchange is working:

```bash
# 1. Get Authentik token (replace with actual token)
AUTHENTIK_TOKEN="your-authentik-token"

# 2. Exchange for backend token
curl -X POST http://localhost:8000/api/v1/auth/exchange \
  -H "Content-Type: application/json" \
  -d "{\"authentik_token\": \"$AUTHENTIK_TOKEN\"}"

# 3. Use backend token
BACKEND_TOKEN="returned-access-token"
curl -H "Authorization: Bearer $BACKEND_TOKEN" \
  http://localhost:8000/api/v1/conversations
```

## Best Practices

1. **Token Lifecycle**:
   - Implement automatic token refresh before expiration
   - Clear tokens on logout
   - Handle token expiration gracefully

2. **Error Handling**:
   - Implement retry logic for network failures
   - Provide clear error messages to users
   - Log authentication failures for monitoring

3. **Performance**:
   - Cache user information to reduce database queries
   - Implement connection pooling for Authentik calls
   - Use Redis for token blacklisting if needed

4. **Monitoring**:
   - Track token exchange success/failure rates
   - Monitor token refresh patterns
   - Alert on unusual authentication patterns
