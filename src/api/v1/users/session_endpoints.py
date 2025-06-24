"""
Session management endpoints.
Handles user session tracking, listing, and termination.
"""

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ....core.auth.session_manager import SessionError, SessionManager, SessionNotFoundError
from ....core.logging import get_logger
from ....infrastructure.database.session import get_db
from ...dependencies.context import get_current_user

router = APIRouter(prefix="/me/sessions", tags=["session-management"])
logger = get_logger(__name__)


class SessionInfo(BaseModel):
    """Session information response schema."""
    session_id: UUID
    tenant_id: UUID
    device_id: UUID | None = None
    session_type: str
    login_method: str
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    is_active: bool
    is_current: bool = False

    # Privacy-safe client information
    user_agent: str | None = None
    client_info: dict = Field(default_factory=dict)

    # Session metadata
    termination_reason: str | None = None
    terminated_at: datetime | None = None


class SessionTerminationRequest(BaseModel):
    """Session termination request schema."""
    reason: str | None = Field(default="user_logout", description="Reason for termination")


class SessionTerminationResponse(BaseModel):
    """Session termination response schema."""
    terminated: bool
    session_id: UUID
    message: str


class BulkSessionTerminationRequest(BaseModel):
    """Bulk session termination request schema."""
    reason: str | None = Field(default="logout_all", description="Reason for bulk termination")
    keep_current: bool = Field(default=True, description="Keep current session active")


class BulkSessionTerminationResponse(BaseModel):
    """Bulk session termination response schema."""
    terminated_count: int
    message: str
    current_session_preserved: bool


class SessionStatistics(BaseModel):
    """Session statistics response schema."""
    total_sessions: int
    active_sessions: int
    expired_sessions: int
    recent_sessions_24h: int
    timestamp: datetime


def _convert_session_to_info(session, current_session_id: UUID | None = None) -> SessionInfo:
    """Convert UserSession model to SessionInfo schema."""
    return SessionInfo(
        session_id=session.id,
        tenant_id=session.tenant_id,
        device_id=session.device_id,
        session_type=session.session_type,
        login_method=session.login_method,
        created_at=session.created_at,
        last_activity=session.last_activity,
        expires_at=session.expires_at,
        is_active=session.is_active,
        is_current=(session.id == current_session_id),
        user_agent=session.user_agent,
        client_info=session.client_info or {},
        termination_reason=session.termination_reason,
        terminated_at=session.terminated_at
    )


@router.get("", response_model=list[SessionInfo])
async def get_user_sessions(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
    active_only: bool = True,
    include_current: bool = True
):
    """
    Get all sessions for the current user.
    
    Args:
        active_only: Only return active (non-expired) sessions
        include_current: Include current session in results
    """
    try:
        session_manager = SessionManager(db)
        current_session_id = current_user.get("session_id")

        sessions = await session_manager.get_user_sessions(
            user_id=current_user["id"],
            active_only=active_only,
            include_current=include_current,
            current_session_id=UUID(current_session_id) if current_session_id else None
        )

        # Convert to response format
        session_infos = []
        for session in sessions:
            session_info = _convert_session_to_info(
                session,
                UUID(current_session_id) if current_session_id else None
            )
            session_infos.append(session_info)

        logger.info(
            "User sessions retrieved",
            user_id=str(current_user["id"]),
            session_count=len(session_infos),
            active_only=active_only
        )

        return session_infos

    except Exception as e:
        logger.error(
            "Failed to get user sessions",
            user_id=str(current_user["id"]),
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve sessions"
        )


@router.get("/current", response_model=SessionInfo)
async def get_current_session(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get information about the current session."""
    try:
        current_session_id = current_user.get("session_id")
        if not current_session_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No session ID available in current user context"
            )

        session_manager = SessionManager(db)

        try:
            session = await session_manager.validate_session(
                UUID(current_session_id),
                update_activity=True
            )
        except SessionNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Current session not found"
            )

        session_info = _convert_session_to_info(session, UUID(current_session_id))
        session_info.is_current = True

        return session_info

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to get current session",
            user_id=str(current_user["id"]),
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve current session"
        )


@router.delete("/{session_id}", response_model=SessionTerminationResponse)
async def terminate_session(
    session_id: UUID,
    termination_request: SessionTerminationRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Terminate a specific session.
    Users can only terminate their own sessions.
    """
    try:
        session_manager = SessionManager(db)

        # First verify the session belongs to the current user
        user_sessions = await session_manager.get_user_sessions(
            user_id=current_user["id"],
            active_only=False  # Include all sessions for ownership verification
        )

        session_belongs_to_user = any(s.id == session_id for s in user_sessions)
        if not session_belongs_to_user:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot terminate session that doesn't belong to you"
            )

        # Terminate the session
        terminated = await session_manager.terminate_session(
            session_id=session_id,
            reason=termination_request.reason,
            terminated_by=current_user["id"]
        )

        if not terminated:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found or already terminated"
            )

        logger.info(
            "Session terminated by user",
            user_id=str(current_user["id"]),
            session_id=str(session_id),
            reason=termination_request.reason
        )

        return SessionTerminationResponse(
            terminated=True,
            session_id=session_id,
            message="Session terminated successfully"
        )

    except HTTPException:
        raise
    except SessionError as e:
        logger.error(
            "Session termination error",
            user_id=str(current_user["id"]),
            session_id=str(session_id),
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(
            "Failed to terminate session",
            user_id=str(current_user["id"]),
            session_id=str(session_id),
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to terminate session"
        )


@router.post("/terminate-all", response_model=BulkSessionTerminationResponse)
async def terminate_all_sessions(
    termination_request: BulkSessionTerminationRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Terminate all sessions for the current user.
    Optionally preserves the current session.
    """
    try:
        session_manager = SessionManager(db)
        current_session_id = None

        if termination_request.keep_current:
            current_session_id = current_user.get("session_id")
            if current_session_id:
                current_session_id = UUID(current_session_id)

        # Terminate all sessions except current (if requested)
        terminated_count = await session_manager.terminate_all_user_sessions(
            user_id=current_user["id"],
            except_session_id=current_session_id,
            reason=termination_request.reason
        )

        logger.info(
            "Bulk session termination completed",
            user_id=str(current_user["id"]),
            terminated_count=terminated_count,
            current_preserved=termination_request.keep_current,
            reason=termination_request.reason
        )

        return BulkSessionTerminationResponse(
            terminated_count=terminated_count,
            message=f"Terminated {terminated_count} sessions",
            current_session_preserved=termination_request.keep_current
        )

    except SessionError as e:
        logger.error(
            "Bulk session termination error",
            user_id=str(current_user["id"]),
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(
            "Failed to terminate all sessions",
            user_id=str(current_user["id"]),
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to terminate sessions"
        )


@router.get("/statistics", response_model=SessionStatistics)
async def get_session_statistics(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get session statistics for the current user.
    Provides insights into session usage patterns.
    """
    try:
        session_manager = SessionManager(db)

        stats = await session_manager.get_session_statistics(
            user_id=current_user["id"]
        )

        return SessionStatistics(
            total_sessions=stats["total_sessions"],
            active_sessions=stats["active_sessions"],
            expired_sessions=stats["expired_sessions"],
            recent_sessions_24h=stats["recent_sessions_24h"],
            timestamp=datetime.fromisoformat(stats["timestamp"].replace('Z', '+00:00'))
        )

    except Exception as e:
        logger.error(
            "Failed to get session statistics",
            user_id=str(current_user["id"]),
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve session statistics"
        )


@router.post("/cleanup-expired")
async def cleanup_expired_sessions(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Cleanup expired sessions for the current user.
    This is typically called automatically, but can be triggered manually.
    """
    try:
        session_manager = SessionManager(db)

        # Get all expired sessions for the user
        all_sessions = await session_manager.get_user_sessions(
            user_id=current_user["id"],
            active_only=False
        )

        expired_sessions = [s for s in all_sessions if s.is_expired() and s.is_active]

        # Terminate expired sessions
        cleanup_count = 0
        for session in expired_sessions:
            terminated = await session_manager.terminate_session(
                session_id=session.id,
                reason="expired_cleanup"
            )
            if terminated:
                cleanup_count += 1

        logger.info(
            "User session cleanup completed",
            user_id=str(current_user["id"]),
            cleanup_count=cleanup_count
        )

        return {
            "cleanup_count": cleanup_count,
            "message": f"Cleaned up {cleanup_count} expired sessions"
        }

    except Exception as e:
        logger.error(
            "Failed to cleanup expired sessions",
            user_id=str(current_user["id"]),
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cleanup expired sessions"
        )
