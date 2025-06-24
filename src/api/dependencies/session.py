"""
Session management dependencies for FastAPI endpoints.
Provides session extraction and validation.
"""
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status

from src.core.logging import get_logger
from src.domain.auth.session_service import SessionInfo, SessionService
from src.infrastructure.auth.dependencies import get_redis_session_service

logger = get_logger(__name__)


async def get_current_session_id(request: Request) -> UUID:
    """
    Extract the current session ID from the request state.
    
    Args:
        request: The FastAPI request object
        
    Returns:
        UUID: The current session ID
        
    Raises:
        HTTPException: If no session ID is found
    """
    if not hasattr(request.state, "session_id") or not request.state.session_id:
        logger.warning("No session ID in request", path=request.url.path)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No session found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        return UUID(request.state.session_id)
    except (ValueError, TypeError) as e:
        logger.error("Invalid session_id in request state", session_id=request.state.session_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session",
        )


async def get_current_session(
    request: Request,
    session_service: SessionService = Depends(get_redis_session_service),
) -> SessionInfo:
    """
    Get the current session information.
    
    Args:
        request: The FastAPI request object
        session_service: The session service instance
        
    Returns:
        SessionInfo: The current session information
        
    Raises:
        HTTPException: If session is not found or invalid
    """
    session_id = await get_current_session_id(request)

    # Get session from service
    session_info = await session_service.get_session(session_id)

    if not session_info:
        logger.error("Session not found", session_id=str(session_id))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Validate session is still active
    is_valid = await session_service.validate_session(session_id)
    if not is_valid:
        logger.warning("Invalid session attempted access", session_id=str(session_id))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )

    logger.debug(
        "Session retrieved via dependency",
        session_id=str(session_id),
        user_id=str(session_info.user_id),
        tenant_id=str(session_info.tenant_id)
    )

    return session_info


async def get_optional_session(
    request: Request,
    session_service: SessionService = Depends(get_redis_session_service),
) -> SessionInfo | None:
    """
    Get the current session if available, otherwise return None.
    Useful for endpoints that support both authenticated and anonymous access.
    
    Args:
        request: The FastAPI request object
        session_service: The session service instance
        
    Returns:
        Optional[SessionInfo]: The current session or None
    """
    if not hasattr(request.state, "session_id") or not request.state.session_id:
        return None

    try:
        session_id = UUID(request.state.session_id)
    except (ValueError, TypeError):
        logger.warning("Invalid session_id format in optional session", session_id=request.state.session_id)
        return None

    # Get session from service
    session_info = await session_service.get_session(session_id)

    if session_info:
        # Validate session
        is_valid = await session_service.validate_session(session_id)
        if is_valid:
            return session_info

    return None


async def require_valid_session(
    session_info: SessionInfo = Depends(get_current_session),
) -> SessionInfo:
    """
    Dependency that ensures the session is valid and active.
    This is essentially the same as get_current_session but with a more explicit name.
    
    Args:
        session_info: The current session (injected by dependency)
        
    Returns:
        SessionInfo: The validated session
    """
    return session_info


async def get_session_metadata(
    session_info: SessionInfo = Depends(get_current_session),
) -> dict:
    """
    Get session metadata as a dictionary.
    Useful for logging or including session info in responses.
    
    Args:
        session_info: The current session
        
    Returns:
        dict: Session metadata
    """
    return {
        "session_id": str(session_info.session_id),
        "user_id": str(session_info.user_id),
        "tenant_id": str(session_info.tenant_id),
        "created_at": session_info.created_at.isoformat(),
        "expires_at": session_info.expires_at.isoformat() if session_info.expires_at else None,
        "last_activity": session_info.last_activity.isoformat() if session_info.last_activity else None,
        "is_active": session_info.is_active,
    }


async def invalidate_current_session(
    session_info: SessionInfo = Depends(get_current_session),
    session_service: SessionService = Depends(get_redis_session_service),
) -> bool:
    """
    Invalidate the current session.
    Useful for logout endpoints.
    
    Args:
        session_info: The current session
        session_service: The session service instance
        
    Returns:
        bool: True if session was invalidated
    """
    success = await session_service.invalidate_session(session_info.session_id)

    if success:
        logger.info(
            "Session invalidated via dependency",
            session_id=str(session_info.session_id),
            user_id=str(session_info.user_id)
        )
    else:
        logger.error(
            "Failed to invalidate session",
            session_id=str(session_info.session_id)
        )

    return success


async def get_active_user_sessions(
    session_info: SessionInfo = Depends(get_current_session),
    session_service: SessionService = Depends(get_redis_session_service),
) -> int:
    """
    Get the count of active sessions for the current user.
    Useful for showing users how many devices they're logged in from.
    
    Args:
        session_info: The current session
        session_service: The session service instance
        
    Returns:
        int: Number of active sessions
    """
    return await session_service.get_active_session_count(session_info.user_id)
