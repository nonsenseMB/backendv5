"""
JWT Authentication Middleware for FastAPI.
Extracts and validates JWT tokens from requests.
"""
import re
from typing import Optional

from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from src.core.config import settings
from src.core.logging import get_logger
from src.infrastructure.auth.exceptions import (
    AuthentikTokenExpiredError,
    AuthentikValidationError,
)
from src.infrastructure.auth.token_exchange import TokenExchangeService
from src.infrastructure.auth.token_validator import TokenValidator

logger = get_logger(__name__)

# Define public endpoints that don't require authentication
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

# Regex patterns for dynamic public endpoints
PUBLIC_ENDPOINT_PATTERNS = [
    re.compile(r"^/api/v1/auth/.*$"),  # All auth endpoints are public
    re.compile(r"^/static/.*$"),       # Static files
    re.compile(r"^/_health/.*$"),      # Health check variants
]


class JWTValidationMiddleware(BaseHTTPMiddleware):
    """
    Middleware to extract and validate JWT tokens from incoming requests.
    Sets user context in request.state for downstream handlers.
    """

    def __init__(self, app):
        super().__init__(app)
        self.token_validator = None
        self.token_exchange = None
        self._initialized = False
    
    async def _ensure_initialized(self):
        """Ensure services are initialized."""
        if not self._initialized:
            from src.infrastructure.auth.dependencies import (
                get_token_validator,
                get_token_exchange_service
            )
            self.token_validator = get_token_validator()
            self.token_exchange = await get_token_exchange_service()
            self._initialized = True

    async def dispatch(self, request: Request, call_next) -> Response:
        """Process the request and validate JWT if required."""
        # Ensure services are initialized
        await self._ensure_initialized()
        
        # Check if endpoint requires authentication
        if self._is_public_endpoint(request.url.path):
            logger.debug("Skipping auth for public endpoint", path=request.url.path)
            return await call_next(request)

        # Extract token
        token = self._extract_token(request)
        if not token:
            logger.warning("Missing authentication token", path=request.url.path)
            return JSONResponse(
                status_code=401,
                content={
                    "error": "unauthorized",
                    "message": "Missing authentication token",
                    "detail": "Bearer token required in Authorization header"
                }
            )

        try:
            # First try to validate as an internal JWT token
            try:
                jwt_manager = self.token_exchange.jwt_manager
                token_payload = jwt_manager.decode_access_token(token)
                
                # Convert internal token payload to claims format
                claims = {
                    "sub": token_payload.sub,
                    "tenant_id": token_payload.tenant_id,
                    "sid": token_payload.session_id,
                    "permissions": token_payload.scopes,  # Map scopes to permissions
                    "groups": [],  # Internal tokens don't have groups
                    "iss": token_payload.iss,
                    "aud": token_payload.aud,
                    "exp": token_payload.exp,
                    "iat": token_payload.iat
                }
                logger.debug("Validated internal JWT token", user_id=token_payload.sub)
                
            except Exception as internal_error:
                # Not an internal token, try validating as Authentik token
                logger.debug("Not an internal token, trying Authentik validation", error=str(internal_error))
                claims = await self.token_validator.validate_access_token(token)
            
            # Set request state with validated claims
            request.state.user_id = claims.get("sub")
            request.state.tenant_id = claims.get("tenant_id", settings.DEFAULT_TENANT_ID)
            request.state.session_id = claims.get("sid")
            request.state.permissions = claims.get("permissions", [])
            request.state.groups = claims.get("groups", [])
            request.state.token_claims = claims
            
            # Log successful authentication
            logger.info(
                "Request authenticated",
                user_id=request.state.user_id,
                tenant_id=request.state.tenant_id,
                path=request.url.path
            )
            
            # Process request
            response = await call_next(request)
            
            # Add security headers
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            
            return response

        except AuthentikTokenExpiredError as e:
            logger.info("Token expired, attempting refresh", error=str(e))
            
            # Check for refresh token
            refresh_token = self._extract_refresh_token(request)
            if refresh_token:
                try:
                    # Attempt token refresh
                    new_tokens = await self._refresh_tokens(refresh_token)
                    
                    # Create response with new tokens
                    response = JSONResponse(
                        status_code=401,
                        content={
                            "error": "token_expired",
                            "message": "Access token expired",
                            "detail": "New tokens provided in response",
                            "tokens": {
                                "access_token": new_tokens["access_token"],
                                "refresh_token": new_tokens["refresh_token"],
                                "token_type": "Bearer",
                                "expires_in": new_tokens["expires_in"]
                            }
                        }
                    )
                    
                    # Set new tokens in cookies if originally from cookies
                    if request.cookies.get("access_token"):
                        response.set_cookie(
                            key="access_token",
                            value=new_tokens["access_token"],
                            httponly=True,
                            secure=True,
                            samesite="lax",
                            max_age=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
                        )
                        response.set_cookie(
                            key="refresh_token",
                            value=new_tokens["refresh_token"],
                            httponly=True,
                            secure=True,
                            samesite="lax",
                            max_age=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
                        )
                    
                    return response
                    
                except Exception as refresh_error:
                    logger.error("Token refresh failed", error=str(refresh_error))
            
            return JSONResponse(
                status_code=401,
                content={
                    "error": "token_expired",
                    "message": "Access token has expired",
                    "detail": str(e)
                }
            )

        except AuthentikValidationError as e:
            logger.warning("Token validation failed", error=str(e), path=request.url.path)
            return JSONResponse(
                status_code=401,
                content={
                    "error": "invalid_token",
                    "message": "Invalid authentication token",
                    "detail": str(e)
                }
            )

        except Exception as e:
            logger.error("Unexpected auth error", error=str(e), path=request.url.path)
            return JSONResponse(
                status_code=500,
                content={
                    "error": "internal_server_error",
                    "message": "Authentication processing failed",
                    "detail": "An unexpected error occurred"
                }
            )

    def _is_public_endpoint(self, path: str) -> bool:
        """Check if the endpoint is public and doesn't require authentication."""
        # Check exact matches
        if path in PUBLIC_ENDPOINTS:
            return True
        
        # Check pattern matches
        for pattern in PUBLIC_ENDPOINT_PATTERNS:
            if pattern.match(path):
                return True
        
        return False

    def _extract_token(self, request: Request) -> Optional[str]:
        """
        Extract JWT token from request.
        Checks Authorization header, then cookies.
        """
        # Try Authorization header first
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]  # Remove "Bearer " prefix
        
        # Try cookie as fallback
        return request.cookies.get("access_token")

    def _extract_refresh_token(self, request: Request) -> Optional[str]:
        """Extract refresh token from request cookies or headers."""
        # Try header first
        refresh_header = request.headers.get("X-Refresh-Token")
        if refresh_header:
            return refresh_header
        
        # Try cookie
        return request.cookies.get("refresh_token")

    async def _refresh_tokens(self, refresh_token: str) -> dict:
        """
        Refresh access token using refresh token.
        Returns new token pair.
        """
        try:
            # Use the JWT manager to refresh tokens
            # This expects internal JWT refresh tokens, not Authentik tokens
            jwt_manager = self.token_exchange.jwt_manager
            new_access_token, new_refresh_token = jwt_manager.refresh_access_token(refresh_token)
            
            return {
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
                "token_type": "Bearer",
                "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
            }
            
        except Exception as e:
            logger.error("Token refresh failed", error=str(e))
            # If internal refresh fails, this might be an Authentik token
            # In a full implementation, we would handle Authentik token refresh via OAuth2 flow
            raise AuthentikValidationError(
                "Token refresh failed. Please re-authenticate with Authentik."
            ) from e


async def jwt_validation_middleware(request: Request, call_next):
    """
    Function-based middleware for JWT validation.
    Can be used as @app.middleware("http") decorator.
    """
    # Create and use the full middleware
    middleware = JWTValidationMiddleware(None)
    return await middleware.dispatch(request, call_next)