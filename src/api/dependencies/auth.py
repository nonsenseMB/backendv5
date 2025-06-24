"""
Authentication dependencies for FastAPI endpoints.
Provides user extraction and authentication requirements.
"""
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.infrastructure.database.models.auth import User
from src.infrastructure.database.session import get_async_session
from src.infrastructure.database.unit_of_work import UnitOfWork

logger = get_logger(__name__)


def get_current_user_id(request: Request) -> UUID:
    """
    Extract the current user ID from the request state.
    
    Args:
        request: The FastAPI request object
        
    Returns:
        UUID: The current user's ID
        
    Raises:
        HTTPException: If no authenticated user is found
    """
    if not hasattr(request.state, "user_id") or not request.state.user_id:
        logger.warning("Unauthenticated request attempted", path=request.url.path)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        return UUID(request.state.user_id)
    except (ValueError, TypeError) as e:
        logger.error("Invalid user_id in request state", user_id=request.state.user_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication state",
        )


async def get_current_user(
    request: Request,
    session: AsyncSession = Depends(get_async_session),
) -> User:
    """
    Get the current authenticated user from the database.
    
    Args:
        request: The FastAPI request object
        session: Database session
        
    Returns:
        User: The authenticated user object
        
    Raises:
        HTTPException: If user is not found or not authenticated
    """
    user_id = await get_current_user_id(request)

    # Get tenant_id from request state for tenant-aware queries
    tenant_id = getattr(request.state, "tenant_id", None)
    if tenant_id:
        try:
            tenant_id = UUID(tenant_id)
        except (ValueError, TypeError):
            tenant_id = None

    # Create unit of work with tenant context
    uow = UnitOfWork(session, tenant_id)

    user = await uow.users.get(user_id)
    if not user:
        logger.error("User not found in database", user_id=str(user_id))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    if not user.is_active:
        logger.warning("Inactive user attempted access", user_id=str(user_id))
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    # Update last seen timestamp
    await uow.users.update_last_seen(user_id)
    await uow.commit()

    logger.debug(
        "User authenticated via dependency",
        user_id=str(user_id),
        email=user.email,
        tenant_id=str(tenant_id) if tenant_id else None
    )

    return user


async def get_optional_user(
    request: Request,
    session: AsyncSession = Depends(get_async_session),
) -> User | None:
    """
    Get the current user if authenticated, otherwise return None.
    Useful for endpoints that support both authenticated and anonymous access.
    
    Args:
        request: The FastAPI request object
        session: Database session
        
    Returns:
        Optional[User]: The authenticated user or None
    """
    if not hasattr(request.state, "user_id") or not request.state.user_id:
        return None

    try:
        user_id = UUID(request.state.user_id)
    except (ValueError, TypeError):
        logger.warning("Invalid user_id format in optional auth", user_id=request.state.user_id)
        return None

    # Get tenant_id from request state
    tenant_id = getattr(request.state, "tenant_id", None)
    if tenant_id:
        try:
            tenant_id = UUID(tenant_id)
        except (ValueError, TypeError):
            tenant_id = None

    # Create unit of work with tenant context
    uow = UnitOfWork(session, tenant_id)

    user = await uow.users.get(user_id)
    if user and user.is_active:
        # Update last seen timestamp
        await uow.users.update_last_seen(user_id)
        await uow.commit()
        return user

    return None


def require_auth(user_id: UUID = Depends(get_current_user_id)) -> UUID:
    """
    Dependency that requires authentication and returns the user ID.
    This is a simpler alternative to get_current_user when you only need the ID.
    
    Args:
        user_id: The current user's ID (injected by dependency)
        
    Returns:
        UUID: The authenticated user's ID
    """
    return user_id


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Dependency that ensures the user is both authenticated and active.
    
    Args:
        current_user: The current user (injected by dependency)
        
    Returns:
        User: The active user
        
    Raises:
        HTTPException: If user is not active
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )
    return current_user


async def get_current_verified_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Dependency that ensures the user is verified (email confirmed).
    
    Args:
        current_user: The current user (injected by dependency)
        
    Returns:
        User: The verified user
        
    Raises:
        HTTPException: If user is not verified
    """
    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email verification required",
        )
    return current_user
