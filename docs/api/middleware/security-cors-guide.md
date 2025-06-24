# Security Headers and CORS Configuration Guide

## Overview

This guide explains how to configure and use the security headers and tenant-aware CORS middleware in the nAI Backend v5.

## Security Headers Middleware

### Purpose

The SecurityHeadersMiddleware adds HTTP security headers to all responses to protect against common web vulnerabilities:

- **X-Content-Type-Options**: Prevents MIME type sniffing
- **X-Frame-Options**: Prevents clickjacking attacks
- **X-XSS-Protection**: Enables XSS protection in older browsers
- **Referrer-Policy**: Controls Referer header information
- **Permissions-Policy**: Controls browser features and APIs
- **Strict-Transport-Security**: Forces HTTPS connections (HSTS)
- **Content-Security-Policy**: Controls resource loading

### Configuration

Add to your FastAPI app in `main.py`:

```python
from src.api.middleware.security import security_headers_middleware

# Add security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    return await security_headers_middleware(request, call_next)
```

### Environment Variables

Configure security headers via environment variables:

```bash
# X-Frame-Options header
X_FRAME_OPTIONS=DENY  # or SAMEORIGIN

# Referrer Policy
REFERRER_POLICY=strict-origin-when-cross-origin

# HSTS Header (HTTPS only)
HSTS_HEADER="max-age=31536000; includeSubDomains; preload"

# Content Security Policy
CSP_REPORT_URI=https://your-domain.com/csp-report
CSP_REPORT_ONLY=false  # Set to true for testing

# Custom security headers
SECURITY_HEADERS='{"X-Custom-Header": "value"}'
```

### Custom Configuration

For advanced configuration, initialize the middleware with options:

```python
from src.api.middleware.security import SecurityHeadersMiddleware

app.add_middleware(
    SecurityHeadersMiddleware,
    x_frame_options="SAMEORIGIN",
    referrer_policy="no-referrer",
    permissions_policy="geolocation=(), camera=()",
    content_security_policy="default-src 'self'; script-src 'self' 'unsafe-eval'",
    strict_transport_security="max-age=63072000"
)
```

## Tenant-Aware CORS Middleware

### Purpose

The TenantAwareCORSMiddleware extends standard CORS functionality with:

- Per-tenant allowed origins
- Dynamic origin validation
- Wildcard pattern support
- Automatic tenant context integration

### Configuration

Replace the standard CORS middleware with the tenant-aware version:

```python
from src.api.middleware.cors import tenant_aware_cors_middleware

# Remove the standard CORSMiddleware
# app.add_middleware(CORSMiddleware, ...)

# Add tenant-aware CORS middleware
@app.middleware("http")
async def cors_middleware(request: Request, call_next):
    """Handle CORS with tenant awareness."""
    return await tenant_aware_cors_middleware(request, call_next)
```

### Global CORS Settings

Configure global CORS settings in environment variables:

```bash
# Allowed origins (JSON array or comma-separated)
CORS_ORIGINS='["http://localhost:3000", "https://app.example.com"]'

# CORS options
CORS_ALLOW_CREDENTIALS=true
CORS_ALLOW_METHODS='["GET", "POST", "PUT", "DELETE", "OPTIONS"]'
CORS_ALLOW_HEADERS='["*"]'
CORS_MAX_AGE=3600
CORS_EXPOSE_HEADERS='["X-Total-Count", "X-Page-Count"]'
```

### Wildcard Origins

Support wildcard patterns in CORS_ORIGINS:

```bash
CORS_ORIGINS='["https://*.example.com", "http://localhost:*"]'
```

This allows:
- `https://app.example.com`
- `https://api.example.com`
- `http://localhost:3000`
- `http://localhost:8080`

### Per-Tenant CORS Configuration

Tenants can have their own allowed origins stored in the database:

```python
# Tenant settings in database
tenant.settings = {
    "cors_origins": [
        "https://tenant1.example.com",
        "https://app.tenant1.com"
    ]
}

# Tenant's custom domain is automatically allowed
tenant.domain = "custom.tenant.com"  # Allows https://custom.tenant.com
```

### Middleware Order

The correct middleware order is crucial:

```python
# 1. Security headers (first - applies to all responses)
@app.middleware("http")
async def security_headers(request: Request, call_next):
    return await security_headers_middleware(request, call_next)

# 2. CORS (before auth - handles preflight)
@app.middleware("http")
async def cors(request: Request, call_next):
    return await tenant_aware_cors_middleware(request, call_next)

# 3. Authentication (validates tokens)
@app.middleware("http")
async def auth(request: Request, call_next):
    return await jwt_validation_middleware(request, call_next)

# 4. Tenant context (after auth)
@app.middleware("http")
async def tenant(request: Request, call_next):
    return await tenant_injection_middleware(request, call_next)

# 5. Request context (after tenant)
@app.middleware("http")
async def context(request: Request, call_next):
    return await request_context_middleware(request, call_next)
```

## WebSocket CORS Support

For WebSocket endpoints, configure the WebSocket URL:

```bash
WEBSOCKET_URL=wss://api.example.com/ws
```

This automatically adds the WebSocket URL to CSP connect-src directive.

## Security Best Practices

### 1. Content Security Policy

Start with a restrictive CSP and gradually relax as needed:

```python
# Development (more permissive)
CSP = "default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'"

# Production (restrictive)
CSP = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'"
```

### 2. HSTS Preloading

For production, enable HSTS preloading:

```bash
HSTS_HEADER="max-age=31536000; includeSubDomains; preload"
```

Then submit your domain to the [HSTS Preload List](https://hstspreload.org/).

### 3. Permissions Policy

Restrict browser features based on your app's needs:

```python
# Restrictive policy (recommended)
permissions_policy="geolocation=(), camera=(), microphone=(), payment=()"

# If you need specific features
ALLOW_GEOLOCATION=true  # Allows geolocation=(self)
```

### 4. CORS Security

- Never use `allow_origins=["*"]` with `allow_credentials=True`
- Validate origins against a whitelist
- Use specific methods instead of `["*"]`
- Limit exposed headers to what's necessary

## Testing

### Test Security Headers

```bash
# Check security headers
curl -I https://your-api.com/health

# Expected headers:
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# X-XSS-Protection: 1; mode=block
# Strict-Transport-Security: max-age=31536000
```

### Test CORS

```bash
# Test preflight request
curl -X OPTIONS https://your-api.com/api/users \
  -H "Origin: https://allowed-origin.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type"

# Test actual request
curl -X GET https://your-api.com/api/users \
  -H "Origin: https://allowed-origin.com"
```

### Test Tenant-Specific CORS

```bash
# With tenant header
curl -X GET https://your-api.com/api/resources \
  -H "Origin: https://tenant-specific.com" \
  -H "X-Tenant-ID: tenant-123"
```

## Troubleshooting

### CORS Issues

1. **Origin not allowed**: Check both global and tenant-specific origins
2. **Preflight failing**: Ensure CORS middleware runs before auth
3. **Credentials not working**: Verify `allow_credentials=True` and origin is not `*`

### Security Header Issues

1. **CSP blocking resources**: Check browser console for CSP violations
2. **HSTS not working**: Ensure you're using HTTPS
3. **Headers missing**: Check middleware order - security headers should be first

### Debugging

Enable debug logging:

```python
import logging
logging.getLogger("src.api.middleware").setLevel(logging.DEBUG)
```

## Cache Management

Clear CORS cache when tenant settings change:

```python
from src.api.cors.cors import clear_tenant_cors_cache

# Clear specific tenant
clear_tenant_cors_cache("tenant-123")

# Clear all tenants
clear_tenant_cors_cache()
```