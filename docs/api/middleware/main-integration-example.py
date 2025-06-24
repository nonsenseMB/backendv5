"""
Example of how to integrate security and CORS middleware in main.py

This shows the recommended middleware order and configuration.
"""
from fastapi import FastAPI, Request
from src.api.middleware import (
    security_headers_middleware,
    tenant_aware_cors_middleware,
    jwt_validation_middleware,
    tenant_injection_middleware,
    request_context_middleware,
)

app = FastAPI()

# IMPORTANT: Middleware order matters!
# They are executed in reverse order of registration for requests,
# and in forward order for responses.

# 1. Security Headers Middleware (first - applies to ALL responses)
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    return await security_headers_middleware(request, call_next)


# 2. CORS Middleware (before auth - handles preflight requests)
@app.middleware("http")
async def handle_cors(request: Request, call_next):
    """Handle CORS with tenant awareness."""
    return await tenant_aware_cors_middleware(request, call_next)


# 3. JWT Authentication Middleware
@app.middleware("http")
async def authenticate_request(request: Request, call_next):
    """JWT validation middleware."""
    return await jwt_validation_middleware(request, call_next)


# 4. Tenant Context Middleware (after auth)
@app.middleware("http")
async def inject_tenant_context(request: Request, call_next):
    """Tenant context injection middleware."""
    return await tenant_injection_middleware(request, call_next)


# 5. Request Context Middleware (after tenant)
@app.middleware("http")
async def setup_request_context(request: Request, call_next):
    """Set up request context for logging and tracking."""
    return await request_context_middleware(request, call_next)


# Optional: Remove the old CORSMiddleware if it exists
# app.add_middleware(
#     CORSMiddleware,  # REMOVE THIS
#     allow_origins=settings.CORS_ORIGINS,
#     allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
#     allow_methods=settings.CORS_ALLOW_METHODS,
#     allow_headers=settings.CORS_ALLOW_HEADERS,
# )