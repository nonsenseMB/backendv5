"""
Tenant-related dependencies for FastAPI endpoints.
Provides tenant extraction and validation.
"""
from typing import Optional
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies.auth import get_current_user
from src.core.context.tenant_context import get_tenant_context, set_tenant_context
from src.core.logging import get_logger
from src.infrastructure.database.models.auth import User
from src.infrastructure.database.models.tenant import Tenant, TenantUser
from src.infrastructure.database.session import get_async_session
from src.infrastructure.database.unit_of_work import UnitOfWork

logger = get_logger(__name__)


async def get_current_tenant_id(request: Request) -> UUID:
    """
    Extract the current tenant ID from the request state.
    
    Args:
        request: The FastAPI request object
        
    Returns:
        UUID: The current tenant's ID
        
    Raises:
        HTTPException: If no tenant context is found
    """
    # First check request state (set by middleware)
    if hasattr(request.state, "tenant_id") and request.state.tenant_id:
        try:
            return UUID(request.state.tenant_id)
        except (ValueError, TypeError) as e:
            logger.error("Invalid tenant_id in request state", tenant_id=request.state.tenant_id, error=str(e))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid tenant context",
            )
    
    # Check context var as fallback
    tenant_id_str = get_tenant_context()
    if tenant_id_str:
        try:
            return UUID(tenant_id_str)
        except (ValueError, TypeError) as e:
            logger.error("Invalid tenant_id in context", tenant_id=tenant_id_str, error=str(e))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid tenant context",
            )
    
    logger.warning("No tenant context found", path=request.url.path)
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Tenant context required",
    )


async def get_current_tenant(
    request: Request,
    session: AsyncSession = Depends(get_async_session),
) -> Tenant:
    """
    Get the current tenant from the database.
    
    Args:
        request: The FastAPI request object
        session: Database session
        
    Returns:
        Tenant: The current tenant object
        
    Raises:
        HTTPException: If tenant is not found or inactive
    """
    tenant_id = await get_current_tenant_id(request)
    
    uow = UnitOfWork(session)
    tenant = await uow.tenants.get(tenant_id)
    
    if not tenant:
        logger.error("Tenant not found in database", tenant_id=str(tenant_id))
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found",
        )
    
    if not tenant.is_active:
        logger.warning("Inactive tenant attempted access", tenant_id=str(tenant_id))
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tenant is inactive",
        )
    
    logger.debug("Tenant retrieved via dependency", tenant_id=str(tenant_id), name=tenant.name)
    return tenant


async def get_optional_tenant(
    request: Request,
    session: AsyncSession = Depends(get_async_session),
) -> Optional[Tenant]:
    """
    Get the current tenant if available, otherwise return None.
    Useful for endpoints that support both tenant-scoped and global access.
    
    Args:
        request: The FastAPI request object
        session: Database session
        
    Returns:
        Optional[Tenant]: The current tenant or None
    """
    # Check request state
    tenant_id_str = getattr(request.state, "tenant_id", None)
    if not tenant_id_str:
        # Check context var
        tenant_id_str = get_tenant_context()
    
    if not tenant_id_str:
        return None
    
    try:
        tenant_id = UUID(tenant_id_str)
    except (ValueError, TypeError):
        logger.warning("Invalid tenant_id format in optional tenant", tenant_id=tenant_id_str)
        return None
    
    uow = UnitOfWork(session)
    tenant = await uow.tenants.get(tenant_id)
    
    if tenant and tenant.is_active:
        return tenant
    
    return None


def require_tenant(tenant_id: UUID = Depends(get_current_tenant_id)) -> UUID:
    """
    Dependency that requires a tenant context and returns the tenant ID.
    This is a simpler alternative to get_current_tenant when you only need the ID.
    
    Args:
        tenant_id: The current tenant's ID (injected by dependency)
        
    Returns:
        UUID: The current tenant's ID
    """
    return tenant_id


async def get_tenant_user(
    current_user: User = Depends(get_current_user),
    current_tenant: Tenant = Depends(get_current_tenant),
    session: AsyncSession = Depends(get_async_session),
) -> TenantUser:
    """
    Get the TenantUser association for the current user and tenant.
    This provides role and permission information.
    
    Args:
        current_user: The authenticated user
        current_tenant: The current tenant
        session: Database session
        
    Returns:
        TenantUser: The tenant-user association
        
    Raises:
        HTTPException: If user is not a member of the tenant
    """
    uow = UnitOfWork(session, current_tenant.id)
    
    if not uow.tenant_users:
        logger.error("Tenant users repository not available", tenant_id=str(current_tenant.id))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Tenant context not properly initialized",
        )
    
    # Find the tenant-user association
    tenant_users = await uow.tenant_users.get_by(user_id=current_user.id, tenant_id=current_tenant.id)
    
    if not tenant_users:
        logger.warning(
            "User not member of tenant",
            user_id=str(current_user.id),
            tenant_id=str(current_tenant.id)
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is not a member of this tenant",
        )
    
    tenant_user = tenant_users[0]  # Should be unique by constraint
    
    if not tenant_user.is_active:
        logger.warning(
            "Inactive tenant membership",
            user_id=str(current_user.id),
            tenant_id=str(current_tenant.id)
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User membership in this tenant is inactive",
        )
    
    return tenant_user


async def require_tenant_role(required_role: str):
    """
    Create a dependency that requires a specific tenant role.
    
    Args:
        required_role: The required role (owner, admin, member, viewer)
        
    Returns:
        Dependency function that validates the role
    """
    async def check_role(
        tenant_user: TenantUser = Depends(get_tenant_user),
    ) -> TenantUser:
        """Check if user has the required role in the tenant."""
        # Define role hierarchy
        role_hierarchy = {
            "viewer": 0,
            "member": 1,
            "admin": 2,
            "owner": 3,
        }
        
        user_role_level = role_hierarchy.get(tenant_user.role, 0)
        required_role_level = role_hierarchy.get(required_role, 0)
        
        if user_role_level < required_role_level:
            logger.warning(
                "Insufficient tenant role",
                user_id=str(tenant_user.user_id),
                tenant_id=str(tenant_user.tenant_id),
                user_role=tenant_user.role,
                required_role=required_role
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{required_role}' or higher required",
            )
        
        return tenant_user
    
    return check_role


async def ensure_tenant_context(
    tenant: Tenant = Depends(get_current_tenant),
) -> Tenant:
    """
    Ensure tenant context is set for the request.
    This is useful for endpoints that need to ensure tenant context is available.
    
    Args:
        tenant: The current tenant (injected by dependency)
        
    Returns:
        Tenant: The current tenant
    """
    # Set the tenant context if not already set
    if not get_tenant_context():
        set_tenant_context(tenant.id)
    
    return tenant