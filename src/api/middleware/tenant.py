"""Tenant context injection middleware for multi-tenant isolation."""
from typing import Optional
from uuid import UUID

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from src.core.config import settings
from src.core.context import (
    clear_tenant_context,
    get_request_context,
    set_tenant_context,
)
from src.core.logging import get_logger
from src.core.logging.audit import AuditEventType, AuditSeverity, log_audit_event

logger = get_logger(__name__)

# Headers that can contain tenant information
TENANT_HEADER_NAMES = [
    "X-Tenant-ID",
    "X-Tenant",
    "Tenant-ID",
]


class TenantContextMiddleware(BaseHTTPMiddleware):
    """Middleware to inject tenant context into all requests for multi-tenant isolation."""
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """Extract tenant ID and inject into context for the request lifecycle."""
        tenant_id = None
        
        try:
            # Extract tenant ID from various sources
            tenant_id = await self._extract_tenant_id(request)
            
            if tenant_id:
                # Validate user has access to this tenant
                if hasattr(request.state, "user_id") and request.state.user_id:
                    is_valid = await self._validate_user_tenant_access(
                        user_id=request.state.user_id,
                        tenant_id=tenant_id
                    )
                    
                    if not is_valid:
                        logger.warning(
                            "User denied access to tenant",
                            user_id=request.state.user_id,
                            requested_tenant_id=tenant_id
                        )
                        
                        # Log security event
                        log_audit_event(
                            event_type=AuditEventType.AUTH_ACCESS_DENIED,
                            user_id=request.state.user_id,
                            tenant_id=tenant_id,
                            severity=AuditSeverity.HIGH,
                            details={
                                "reason": "Invalid tenant access",
                                "path": request.url.path
                            }
                        )
                        
                        from fastapi.responses import JSONResponse
                        return JSONResponse(
                            status_code=403,
                            content={
                                "error": "forbidden",
                                "message": "Access denied to requested tenant",
                                "detail": "User does not have permission to access this tenant"
                            }
                        )
                
                # Set tenant context
                set_tenant_context(tenant_id)
                logger.debug(
                    "Tenant context set",
                    tenant_id=tenant_id,
                    path=request.url.path
                )
            else:
                # Use default tenant if enabled and no tenant specified
                if settings.ENABLE_MULTI_TENANCY and settings.DEFAULT_TENANT_ID:
                    tenant_id = settings.DEFAULT_TENANT_ID
                    set_tenant_context(tenant_id)
                    logger.debug(
                        "Using default tenant",
                        tenant_id=tenant_id,
                        path=request.url.path
                    )
            
            # Process request
            response = await call_next(request)
            
            # Add tenant ID to response headers for debugging
            if tenant_id:
                response.headers["X-Tenant-ID"] = str(tenant_id)
            
            return response
            
        except Exception as e:
            logger.error(
                "Error in tenant middleware",
                error=str(e),
                tenant_id=tenant_id,
                path=request.url.path
            )
            raise
        finally:
            # Always clear tenant context after request
            clear_tenant_context()
    
    async def _extract_tenant_id(self, request: Request) -> Optional[str]:
        """Extract tenant ID from request.
        
        Priority order:
        1. JWT claims (if authenticated)
        2. Request headers
        3. Query parameters
        4. Request state (if set by other middleware)
        """
        # 1. Check JWT claims first (most authoritative)
        if hasattr(request.state, "tenant_id") and request.state.tenant_id:
            return str(request.state.tenant_id)
        
        # 2. Check request headers
        for header_name in TENANT_HEADER_NAMES:
            tenant_id = request.headers.get(header_name)
            if tenant_id:
                logger.debug(
                    "Tenant ID found in header",
                    header=header_name,
                    tenant_id=tenant_id
                )
                return tenant_id
        
        # 3. Check query parameters
        tenant_id = request.query_params.get("tenant_id")
        if tenant_id:
            logger.debug(
                "Tenant ID found in query params",
                tenant_id=tenant_id
            )
            return tenant_id
        
        # 4. Check if already in request context (from logging middleware)
        request_context = get_request_context()
        if request_context and request_context.tenant_id:
            return request_context.tenant_id
        
        return None
    
    async def _validate_user_tenant_access(
        self,
        user_id: str,
        tenant_id: str
    ) -> bool:
        """Validate that a user has access to the specified tenant.
        
        Args:
            user_id: The user's ID
            tenant_id: The tenant ID to validate
            
        Returns:
            True if the user has access, False otherwise
        """
        # If multi-tenancy is disabled, allow all access
        if not settings.ENABLE_MULTI_TENANCY:
            return True
        
        try:
            # Check database for user-tenant membership
            from uuid import UUID
            from src.infrastructure.database.session import AsyncSessionLocal
            from src.infrastructure.database.repositories.tenant import TenantUserRepository
            
            # Create database session
            async with AsyncSessionLocal() as session:
                # Import the model
                from src.infrastructure.database.models.tenant import TenantUser
                
                # Create repository with the target tenant context
                repo = TenantUserRepository(
                    model=TenantUser,
                    session=session,
                    tenant_id=UUID(tenant_id)
                )
                
                # Check if user has membership in this tenant
                membership = await repo.get_membership(UUID(user_id))
                
                if membership and membership.is_active:
                    logger.debug(
                        "User has valid tenant membership",
                        user_id=user_id,
                        tenant_id=tenant_id,
                        role=membership.role
                    )
                    return True
                else:
                    logger.warning(
                        "User has no active membership in tenant",
                        user_id=user_id,
                        tenant_id=tenant_id,
                        membership_exists=membership is not None,
                        is_active=membership.is_active if membership else False
                    )
                    return False
                    
        except Exception as e:
            logger.error(
                "Error validating user-tenant access",
                error=str(e),
                user_id=user_id,
                tenant_id=tenant_id
            )
            # In case of database error, deny access for security
            return False


async def tenant_injection_middleware(request: Request, call_next):
    """Function-based tenant middleware for FastAPI.
    
    Can be used as @app.middleware("http") decorator.
    """
    middleware = TenantContextMiddleware(None)
    return await middleware.dispatch(request, call_next)