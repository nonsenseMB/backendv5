"""
User session management service.
Handles session lifecycle, tracking, and security monitoring.
"""

import hashlib
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import desc
from sqlalchemy.orm import Session

from ...infrastructure.database.models.auth import User
from ...infrastructure.database.models.tenant import Tenant
from ...infrastructure.database.models.user_session import SessionActivity, SessionSecurityEvent, UserSession
from ..logging import get_logger
from ..logging.audit import AuditEventType, AuditSeverity, log_audit_event

logger = get_logger(__name__)


class SessionError(Exception):
    """Base exception for session management errors."""
    pass


class SessionNotFoundError(SessionError):
    """Session not found or invalid."""
    pass


class SessionExpiredError(SessionError):
    """Session has expired."""
    pass


class SessionManager:
    """
    Comprehensive session management service.
    Handles session creation, validation, tracking, and termination.
    """

    def __init__(self, db: Session, default_session_duration: timedelta = timedelta(hours=24)):
        self.db = db
        self.default_session_duration = default_session_duration

    async def create_session(
        self,
        user_id: UUID,
        tenant_id: UUID,
        ip_address: str | None = None,
        user_agent: str | None = None,
        device_id: UUID | None = None,
        authentik_session_id: str | None = None,
        session_type: str = "web",
        login_method: str = "sso",
        session_duration: timedelta | None = None,
        client_info: dict[str, Any] | None = None
    ) -> UserSession:
        """
        Create a new user session with comprehensive tracking.
        
        Args:
            user_id: User ID
            tenant_id: Tenant ID for session context
            ip_address: Client IP address (will be hashed)
            user_agent: Client user agent string
            device_id: Associated device ID (optional)
            authentik_session_id: External Authentik session ID
            session_type: Type of session (web, mobile, api)
            login_method: Authentication method used
            session_duration: Custom session duration
            client_info: Additional client information
            
        Returns:
            Created UserSession object
        """
        try:
            # Validate user and tenant exist
            user = self.db.query(User).filter(User.id == user_id, User.is_active == True).first()
            if not user:
                raise SessionError(f"User {user_id} not found or inactive")

            tenant = self.db.query(Tenant).filter(Tenant.id == tenant_id, Tenant.is_active == True).first()
            if not tenant:
                raise SessionError(f"Tenant {tenant_id} not found or inactive")

            # Calculate session expiration
            duration = session_duration or self.default_session_duration
            expires_at = datetime.utcnow() + duration

            # Hash IP address for privacy
            ip_hash = None
            if ip_address:
                ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()

            # Create session
            session = UserSession(
                user_id=user_id,
                tenant_id=tenant_id,
                device_id=device_id,
                authentik_session_id=authentik_session_id,
                ip_address_hash=ip_hash,
                user_agent=user_agent,
                client_info=client_info or {},
                expires_at=expires_at,
                session_type=session_type,
                login_method=login_method,
                is_active=True
            )

            self.db.add(session)
            self.db.commit()
            self.db.refresh(session)

            # Log session creation
            await self._log_session_activity(
                session.id,
                "session_created",
                details={
                    "session_type": session_type,
                    "login_method": login_method,
                    "device_id": str(device_id) if device_id else None,
                    "duration_hours": duration.total_seconds() / 3600
                }
            )

            # Check for concurrent sessions (security monitoring)
            await self._check_concurrent_sessions(user_id, session.id)

            logger.info(
                "Session created successfully",
                session_id=str(session.id),
                user_id=str(user_id),
                tenant_id=str(tenant_id),
                session_type=session_type,
                expires_at=expires_at.isoformat()
            )

            return session

        except Exception as e:
            self.db.rollback()
            logger.error(
                "Failed to create session",
                user_id=str(user_id),
                tenant_id=str(tenant_id),
                error=str(e)
            )
            raise SessionError(f"Session creation failed: {str(e)}")

    async def validate_session(self, session_id: UUID, update_activity: bool = True) -> UserSession:
        """
        Validate a session and optionally update activity timestamp.
        
        Args:
            session_id: Session ID to validate
            update_activity: Whether to update last_activity timestamp
            
        Returns:
            Valid UserSession object
            
        Raises:
            SessionNotFoundError: If session doesn't exist
            SessionExpiredError: If session has expired
        """
        try:
            session = self.db.query(UserSession).filter(UserSession.id == session_id).first()

            if not session:
                raise SessionNotFoundError(f"Session {session_id} not found")

            if not session.is_active:
                raise SessionNotFoundError(f"Session {session_id} is inactive")

            if session.is_expired():
                # Mark session as expired
                session.terminate("expired")
                self.db.commit()

                await self._log_session_activity(
                    session_id,
                    "session_expired",
                    details={"expired_at": datetime.utcnow().isoformat()}
                )

                raise SessionExpiredError(f"Session {session_id} has expired")

            # Update activity if requested
            if update_activity:
                session.update_activity()
                self.db.commit()

            return session

        except (SessionNotFoundError, SessionExpiredError):
            raise
        except Exception as e:
            logger.error(
                "Session validation error",
                session_id=str(session_id),
                error=str(e)
            )
            raise SessionError(f"Session validation failed: {str(e)}")

    async def get_user_sessions(
        self,
        user_id: UUID,
        active_only: bool = True,
        include_current: bool = True,
        current_session_id: UUID | None = None
    ) -> list[UserSession]:
        """
        Get all sessions for a user.
        
        Args:
            user_id: User ID
            active_only: Only return active sessions
            include_current: Include current session in results
            current_session_id: Current session ID (to exclude if include_current=False)
            
        Returns:
            List of UserSession objects
        """
        try:
            query = self.db.query(UserSession).filter(UserSession.user_id == user_id)

            if active_only:
                query = query.filter(
                    UserSession.is_active == True,
                    UserSession.expires_at > datetime.utcnow()
                )

            if not include_current and current_session_id:
                query = query.filter(UserSession.id != current_session_id)

            sessions = query.order_by(desc(UserSession.last_activity)).all()

            logger.debug(
                "Retrieved user sessions",
                user_id=str(user_id),
                session_count=len(sessions),
                active_only=active_only
            )

            return sessions

        except Exception as e:
            logger.error(
                "Failed to get user sessions",
                user_id=str(user_id),
                error=str(e)
            )
            raise SessionError(f"Failed to get user sessions: {str(e)}")

    async def terminate_session(
        self,
        session_id: UUID,
        reason: str = "logout",
        terminated_by: UUID | None = None
    ) -> bool:
        """
        Terminate a specific session.
        
        Args:
            session_id: Session ID to terminate
            reason: Reason for termination
            terminated_by: User ID who initiated termination (for admin actions)
            
        Returns:
            True if session was terminated, False if not found
        """
        try:
            session = self.db.query(UserSession).filter(UserSession.id == session_id).first()

            if not session:
                logger.warning("Attempted to terminate non-existent session", session_id=str(session_id))
                return False

            if not session.is_active:
                logger.debug("Session already terminated", session_id=str(session_id))
                return True

            # Terminate session
            session.terminate(reason)
            self.db.commit()

            # Log termination
            await self._log_session_activity(
                session_id,
                "session_terminated",
                details={
                    "reason": reason,
                    "terminated_by": str(terminated_by) if terminated_by else None,
                    "duration_minutes": (datetime.utcnow() - session.created_at).total_seconds() / 60
                }
            )

            # Audit log
            await log_audit_event(
                event_type=AuditEventType.AUTH_TOKEN_REFRESHED,  # Closest available event
                severity=AuditSeverity.MEDIUM,
                details={
                    "action": "session_terminated",
                    "session_id": str(session_id),
                    "user_id": str(session.user_id),
                    "reason": reason,
                    "terminated_by": str(terminated_by) if terminated_by else "self"
                }
            )

            logger.info(
                "Session terminated",
                session_id=str(session_id),
                user_id=str(session.user_id),
                reason=reason,
                terminated_by=str(terminated_by) if terminated_by else "self"
            )

            return True

        except Exception as e:
            self.db.rollback()
            logger.error(
                "Failed to terminate session",
                session_id=str(session_id),
                error=str(e)
            )
            raise SessionError(f"Session termination failed: {str(e)}")

    async def terminate_all_user_sessions(
        self,
        user_id: UUID,
        except_session_id: UUID | None = None,
        reason: str = "logout_all"
    ) -> int:
        """
        Terminate all sessions for a user.
        
        Args:
            user_id: User ID
            except_session_id: Session ID to exclude from termination
            reason: Reason for termination
            
        Returns:
            Number of sessions terminated
        """
        try:
            query = self.db.query(UserSession).filter(
                UserSession.user_id == user_id,
                UserSession.is_active == True
            )

            if except_session_id:
                query = query.filter(UserSession.id != except_session_id)

            sessions = query.all()
            terminated_count = 0

            for session in sessions:
                session.terminate(reason)
                terminated_count += 1

                # Log each termination
                await self._log_session_activity(
                    session.id,
                    "session_terminated_bulk",
                    details={
                        "reason": reason,
                        "bulk_operation": True,
                        "total_terminated": len(sessions)
                    }
                )

            if terminated_count > 0:
                self.db.commit()

                # Audit log for bulk termination
                await log_audit_event(
                    event_type=AuditEventType.AUTH_TOKEN_REFRESHED,  # Closest available event
                    severity=AuditSeverity.HIGH,
                    details={
                        "action": "bulk_session_termination",
                        "user_id": str(user_id),
                        "sessions_terminated": terminated_count,
                        "reason": reason,
                        "except_session": str(except_session_id) if except_session_id else None
                    }
                )

                logger.info(
                    "Bulk session termination completed",
                    user_id=str(user_id),
                    terminated_count=terminated_count,
                    reason=reason
                )

            return terminated_count

        except Exception as e:
            self.db.rollback()
            logger.error(
                "Failed to terminate user sessions",
                user_id=str(user_id),
                error=str(e)
            )
            raise SessionError(f"Bulk session termination failed: {str(e)}")

    async def cleanup_expired_sessions(self, batch_size: int = 100) -> int:
        """
        Clean up expired sessions from the database.
        
        Args:
            batch_size: Number of sessions to process in each batch
            
        Returns:
            Number of sessions cleaned up
        """
        try:
            cleaned_count = 0

            while True:
                # Get batch of expired sessions
                expired_sessions = (
                    self.db.query(UserSession)
                    .filter(
                        UserSession.is_active == True,
                        UserSession.expires_at <= datetime.utcnow()
                    )
                    .limit(batch_size)
                    .all()
                )

                if not expired_sessions:
                    break

                # Terminate expired sessions
                for session in expired_sessions:
                    session.terminate("expired")
                    cleaned_count += 1

                self.db.commit()

                # Log cleanup batch
                logger.debug(
                    "Expired sessions cleanup batch",
                    batch_size=len(expired_sessions),
                    total_cleaned=cleaned_count
                )

            if cleaned_count > 0:
                logger.info(
                    "Session cleanup completed",
                    cleaned_count=cleaned_count
                )

            return cleaned_count

        except Exception as e:
            self.db.rollback()
            logger.error(
                "Session cleanup failed",
                error=str(e)
            )
            raise SessionError(f"Session cleanup failed: {str(e)}")

    async def _log_session_activity(
        self,
        session_id: UUID,
        activity_type: str,
        details: dict[str, Any] | None = None,
        endpoint: str | None = None,
        http_method: str | None = None,
        status_code: int | None = None,
        success: bool | None = None
    ) -> None:
        """Log session activity for tracking and security monitoring."""
        try:
            activity = SessionActivity(
                session_id=session_id,
                activity_type=activity_type,
                endpoint=endpoint,
                http_method=http_method,
                status_code=status_code,
                details=details or {},
                success=success
            )

            self.db.add(activity)
            self.db.commit()

        except Exception as e:
            logger.warning(
                "Failed to log session activity",
                session_id=str(session_id),
                activity_type=activity_type,
                error=str(e)
            )

    async def _check_concurrent_sessions(self, user_id: UUID, current_session_id: UUID) -> None:
        """Check for suspicious concurrent session activity."""
        try:
            # Count active sessions for user
            active_sessions = (
                self.db.query(UserSession)
                .filter(
                    UserSession.user_id == user_id,
                    UserSession.is_active == True,
                    UserSession.expires_at > datetime.utcnow()
                )
                .count()
            )

            # Check if too many concurrent sessions (configurable threshold)
            max_concurrent_sessions = 5  # This could be a setting

            if active_sessions > max_concurrent_sessions:
                # Log security event
                security_event = SessionSecurityEvent(
                    user_id=user_id,
                    session_id=current_session_id,
                    event_type="excessive_concurrent_sessions",
                    severity="medium",
                    description=f"User has {active_sessions} concurrent sessions (max: {max_concurrent_sessions})",
                    details={
                        "active_sessions": active_sessions,
                        "max_allowed": max_concurrent_sessions,
                        "current_session": str(current_session_id)
                    }
                )

                self.db.add(security_event)
                self.db.commit()

                logger.warning(
                    "Excessive concurrent sessions detected",
                    user_id=str(user_id),
                    active_sessions=active_sessions,
                    max_allowed=max_concurrent_sessions
                )

        except Exception as e:
            logger.error(
                "Failed to check concurrent sessions",
                user_id=str(user_id),
                error=str(e)
            )

    async def get_session_statistics(self, user_id: UUID | None = None) -> dict[str, Any]:
        """
        Get session statistics for monitoring and analytics.
        
        Args:
            user_id: If provided, get stats for specific user, otherwise global stats
            
        Returns:
            Dictionary with session statistics
        """
        try:
            base_query = self.db.query(UserSession)

            if user_id:
                base_query = base_query.filter(UserSession.user_id == user_id)

            # Current statistics
            total_sessions = base_query.count()
            active_sessions = base_query.filter(
                UserSession.is_active == True,
                UserSession.expires_at > datetime.utcnow()
            ).count()
            expired_sessions = base_query.filter(
                UserSession.expires_at <= datetime.utcnow()
            ).count()

            # Recent activity (last 24 hours)
            recent_cutoff = datetime.utcnow() - timedelta(hours=24)
            recent_sessions = base_query.filter(
                UserSession.created_at >= recent_cutoff
            ).count()

            stats = {
                "total_sessions": total_sessions,
                "active_sessions": active_sessions,
                "expired_sessions": expired_sessions,
                "recent_sessions_24h": recent_sessions,
                "user_id": str(user_id) if user_id else "global",
                "timestamp": datetime.utcnow().isoformat()
            }

            logger.debug(
                "Session statistics generated",
                user_id=str(user_id) if user_id else "global",
                stats=stats
            )

            return stats

        except Exception as e:
            logger.error(
                "Failed to get session statistics",
                user_id=str(user_id) if user_id else "global",
                error=str(e)
            )
            raise SessionError(f"Failed to get session statistics: {str(e)}")
