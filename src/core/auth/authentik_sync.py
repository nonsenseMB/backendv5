"""
Authentik session synchronization service.
Manages synchronization between internal sessions and Authentik sessions.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
import asyncio

from sqlalchemy.orm import Session

from ...infrastructure.database.models.auth import User
from ...infrastructure.database.models.user_session import SessionSecurityEvent, UserSession
from ..config import settings
from ..logging import get_logger
from .session_manager import SessionManager

logger = get_logger(__name__)


class AuthentikSyncError(Exception):
    """Base exception for Authentik synchronization errors."""
    pass


class AuthentikConnectionError(AuthentikSyncError):
    """Cannot connect to Authentik server."""
    pass


class AuthentikAuthError(AuthentikSyncError):
    """Authentication error with Authentik."""
    pass


class AuthentikSessionSync:
    """
    Service for synchronizing sessions with Authentik.
    Handles session validation, cleanup, and security monitoring.
    """

    def __init__(self, db: Session):
        self.db = db
        self.authentik_base_url = getattr(settings, 'AUTHENTIK_BASE_URL', 'http://localhost:9000')
        self.authentik_token = getattr(settings, 'AUTHENTIK_API_TOKEN', '')
        self.sync_enabled = bool(self.authentik_token and self.authentik_base_url and AIOHTTP_AVAILABLE)

        if not self.sync_enabled:
            logger.warning(
                "Authentik sync disabled - missing configuration",
                has_url=bool(self.authentik_base_url),
                has_token=bool(self.authentik_token),
                has_aiohttp=AIOHTTP_AVAILABLE
            )

    async def sync_user_sessions(self, user_id: UUID) -> dict[str, Any]:
        """
        Synchronize all sessions for a specific user with Authentik.
        
        Args:
            user_id: User ID to sync sessions for
            
        Returns:
            Dictionary with sync results and statistics
        """
        if not self.sync_enabled:
            logger.debug("Authentik sync disabled, skipping user session sync")
            return {"synced": False, "reason": "sync_disabled"}

        try:
            # Get user information
            user = self.db.query(User).filter(User.id == user_id).first()
            if not user:
                raise AuthentikSyncError(f"User {user_id} not found")

            # Get internal sessions for user
            internal_sessions = (
                self.db.query(UserSession)
                .filter(
                    UserSession.user_id == user_id,
                    UserSession.is_active == True,
                    UserSession.authentik_session_id.isnot(None)
                )
                .all()
            )

            # Get Authentik sessions for user
            authentik_sessions = await self._get_authentik_sessions(user.external_id)

            # Compare and sync sessions
            sync_results = await self._sync_session_lists(
                internal_sessions,
                authentik_sessions,
                user_id
            )

            logger.info(
                "User session sync completed",
                user_id=str(user_id),
                external_id=user.external_id,
                internal_sessions=len(internal_sessions),
                authentik_sessions=len(authentik_sessions),
                **sync_results
            )

            return {
                "synced": True,
                "user_id": str(user_id),
                "internal_sessions": len(internal_sessions),
                "authentik_sessions": len(authentik_sessions),
                **sync_results
            }

        except Exception as e:
            logger.error(
                "User session sync failed",
                user_id=str(user_id),
                error=str(e)
            )
            raise AuthentikSyncError(f"User session sync failed: {str(e)}")

    async def sync_all_sessions(self, batch_size: int = 50) -> dict[str, Any]:
        """
        Synchronize all active sessions with Authentik.
        Processes users in batches to avoid overwhelming the system.
        
        Args:
            batch_size: Number of users to process in each batch
            
        Returns:
            Dictionary with overall sync results
        """
        if not self.sync_enabled:
            logger.debug("Authentik sync disabled, skipping full session sync")
            return {"synced": False, "reason": "sync_disabled"}

        try:
            # Get all users with active sessions
            users_with_sessions = (
                self.db.query(User.id)
                .join(UserSession, User.id == UserSession.user_id)
                .filter(
                    UserSession.is_active == True,
                    UserSession.expires_at > datetime.utcnow(),
                    UserSession.authentik_session_id.isnot(None)
                )
                .distinct()
                .all()
            )

            user_ids = [user.id for user in users_with_sessions]
            total_users = len(user_ids)

            # Process users in batches
            sync_stats = {
                "total_users": total_users,
                "processed_users": 0,
                "successful_syncs": 0,
                "failed_syncs": 0,
                "sessions_terminated": 0,
                "sessions_created": 0,
                "errors": []
            }

            for i in range(0, total_users, batch_size):
                batch_user_ids = user_ids[i:i + batch_size]

                # Process batch concurrently
                batch_tasks = [
                    self._sync_user_safe(user_id)
                    for user_id in batch_user_ids
                ]

                batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)

                # Process batch results
                for user_id, result in zip(batch_user_ids, batch_results, strict=False):
                    sync_stats["processed_users"] += 1

                    if isinstance(result, Exception):
                        sync_stats["failed_syncs"] += 1
                        sync_stats["errors"].append({
                            "user_id": str(user_id),
                            "error": str(result)
                        })
                    else:
                        sync_stats["successful_syncs"] += 1
                        if isinstance(result, dict):
                            sync_stats["sessions_terminated"] += result.get("terminated", 0)
                            sync_stats["sessions_created"] += result.get("created", 0)

                # Add delay between batches to avoid rate limiting
                if i + batch_size < total_users:
                    await asyncio.sleep(1)

            logger.info(
                "Full session sync completed",
                **sync_stats
            )

            return {
                "synced": True,
                **sync_stats
            }

        except Exception as e:
            logger.error(
                "Full session sync failed",
                error=str(e)
            )
            raise AuthentikSyncError(f"Full session sync failed: {str(e)}")

    async def validate_authentik_session(
        self,
        authentik_session_id: str,
        user_id: UUID
    ) -> bool:
        """
        Validate that an Authentik session is still active.
        
        Args:
            authentik_session_id: Authentik session ID to validate
            user_id: User ID for context
            
        Returns:
            True if session is valid, False otherwise
        """
        if not self.sync_enabled:
            logger.debug("Authentik sync disabled, assuming session valid")
            return True

        try:
            # Get user external ID
            user = self.db.query(User).filter(User.id == user_id).first()
            if not user:
                logger.warning("User not found for session validation", user_id=str(user_id))
                return False

            # Check if session exists in Authentik
            authentik_sessions = await self._get_authentik_sessions(user.external_id)

            for session in authentik_sessions:
                if session.get("session_id") == authentik_session_id:
                    # Check if session is still active
                    expires_at = session.get("expires_at")
                    if expires_at:
                        session_expires = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                        return session_expires > datetime.utcnow()
                    return True

            logger.debug(
                "Authentik session not found or expired",
                authentik_session_id=authentik_session_id,
                user_id=str(user_id)
            )
            return False

        except Exception as e:
            logger.error(
                "Error validating Authentik session",
                authentik_session_id=authentik_session_id,
                user_id=str(user_id),
                error=str(e)
            )
            # In case of error, assume session is invalid for security
            return False

    async def terminate_authentik_session(
        self,
        authentik_session_id: str,
        user_id: UUID
    ) -> bool:
        """
        Terminate a session in Authentik.
        
        Args:
            authentik_session_id: Authentik session ID to terminate
            user_id: User ID for context
            
        Returns:
            True if termination was successful, False otherwise
        """
        if not self.sync_enabled:
            logger.debug("Authentik sync disabled, cannot terminate session")
            return False

        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {self.authentik_token}",
                    "Content-Type": "application/json"
                }

                # Terminate session via Authentik API
                url = f"{self.authentik_base_url}/api/v3/core/user_sessions/{authentik_session_id}/"

                async with session.delete(url, headers=headers) as response:
                    if response.status == 204:
                        logger.info(
                            "Authentik session terminated successfully",
                            authentik_session_id=authentik_session_id,
                            user_id=str(user_id)
                        )
                        return True
                    elif response.status == 404:
                        logger.debug(
                            "Authentik session not found (already terminated?)",
                            authentik_session_id=authentik_session_id,
                            user_id=str(user_id)
                        )
                        return True  # Consider this success
                    else:
                        logger.warning(
                            "Failed to terminate Authentik session",
                            authentik_session_id=authentik_session_id,
                            user_id=str(user_id),
                            status=response.status,
                            response_text=await response.text()
                        )
                        return False

        except Exception as e:
            logger.error(
                "Error terminating Authentik session",
                authentik_session_id=authentik_session_id,
                user_id=str(user_id),
                error=str(e)
            )
            return False

    async def _get_authentik_sessions(self, user_external_id: str) -> list[dict[str, Any]]:
        """Get active sessions for a user from Authentik."""
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {self.authentik_token}",
                    "Content-Type": "application/json"
                }

                # Get user sessions from Authentik
                url = f"{self.authentik_base_url}/api/v3/core/user_sessions/"
                params = {"user": user_external_id}

                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("results", [])
                    elif response.status == 401:
                        raise AuthentikAuthError("Invalid Authentik API token")
                    elif response.status == 404:
                        logger.debug("User not found in Authentik", user_external_id=user_external_id)
                        return []
                    else:
                        logger.warning(
                            "Failed to get Authentik sessions",
                            user_external_id=user_external_id,
                            status=response.status
                        )
                        return []

        except aiohttp.ClientError as e:
            raise AuthentikConnectionError(f"Cannot connect to Authentik: {str(e)}")
        except Exception as e:
            logger.error(
                "Error getting Authentik sessions",
                user_external_id=user_external_id,
                error=str(e)
            )
            return []

    async def _sync_session_lists(
        self,
        internal_sessions: list[UserSession],
        authentik_sessions: list[dict[str, Any]],
        user_id: UUID
    ) -> dict[str, Any]:
        """Synchronize internal and Authentik session lists."""
        session_manager = SessionManager(self.db)

        # Create lookup maps
        internal_by_authentik_id = {
            s.authentik_session_id: s
            for s in internal_sessions
            if s.authentik_session_id
        }

        authentik_by_id = {
            s.get("session_id"): s
            for s in authentik_sessions
            if s.get("session_id")
        }

        terminated = 0
        created = 0
        validated = 0

        # Check internal sessions against Authentik
        for internal_session in internal_sessions:
            authentik_id = internal_session.authentik_session_id

            if authentik_id not in authentik_by_id:
                # Internal session not found in Authentik - terminate it
                await session_manager.terminate_session(
                    internal_session.id,
                    reason="authentik_sync_not_found"
                )
                terminated += 1

                # Log security event
                await self._log_security_event(
                    user_id,
                    "session_sync_terminated",
                    "Session terminated - not found in Authentik",
                    {"session_id": str(internal_session.id), "authentik_session_id": authentik_id}
                )
            else:
                # Validate session expiration
                authentik_session = authentik_by_id[authentik_id]
                expires_at = authentik_session.get("expires_at")

                if expires_at:
                    authentik_expires = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))

                    if authentik_expires <= datetime.utcnow():
                        # Authentik session expired - terminate internal session
                        await session_manager.terminate_session(
                            internal_session.id,
                            reason="authentik_sync_expired"
                        )
                        terminated += 1
                    else:
                        validated += 1
                else:
                    validated += 1

        # Note: We don't automatically create internal sessions for Authentik sessions
        # because that would require additional context (tenant, device, etc.)
        # Such sessions should be created during the authentication flow

        return {
            "terminated": terminated,
            "created": created,
            "validated": validated
        }

    async def _sync_user_safe(self, user_id: UUID) -> dict[str, Any]:
        """Safe wrapper for user sync that doesn't raise exceptions."""
        try:
            return await self.sync_user_sessions(user_id)
        except Exception as e:
            logger.error(
                "Safe user sync failed",
                user_id=str(user_id),
                error=str(e)
            )
            return {"error": str(e)}

    async def _log_security_event(
        self,
        user_id: UUID,
        event_type: str,
        description: str,
        details: dict[str, Any]
    ) -> None:
        """Log a security event related to session synchronization."""
        try:
            security_event = SessionSecurityEvent(
                user_id=user_id,
                event_type=event_type,
                severity="medium",
                description=description,
                details=details
            )

            self.db.add(security_event)
            self.db.commit()

        except Exception as e:
            logger.error(
                "Failed to log security event",
                user_id=str(user_id),
                event_type=event_type,
                error=str(e)
            )


async def cleanup_orphaned_sessions(db: Session) -> int:
    """
    Cleanup internal sessions that are no longer valid in Authentik.
    Can be run as a periodic task.
    
    Args:
        db: Database session
        
    Returns:
        Number of sessions cleaned up
    """
    sync_service = AuthentikSessionSync(db)

    if not sync_service.sync_enabled:
        logger.debug("Authentik sync disabled, skipping orphaned session cleanup")
        return 0

    try:
        # Get all active sessions with Authentik session IDs
        active_sessions = (
            db.query(UserSession)
            .filter(
                UserSession.is_active == True,
                UserSession.expires_at > datetime.utcnow(),
                UserSession.authentik_session_id.isnot(None)
            )
            .all()
        )

        cleaned_count = 0
        session_manager = SessionManager(db)

        # Check each session against Authentik
        for session in active_sessions:
            is_valid = await sync_service.validate_authentik_session(
                session.authentik_session_id,
                session.user_id
            )

            if not is_valid:
                await session_manager.terminate_session(
                    session.id,
                    reason="authentik_orphaned_cleanup"
                )
                cleaned_count += 1

        logger.info(
            "Orphaned session cleanup completed",
            total_checked=len(active_sessions),
            cleaned_count=cleaned_count
        )

        return cleaned_count

    except Exception as e:
        logger.error(
            "Orphaned session cleanup failed",
            error=str(e)
        )
        return 0
