"""
WebSocket presence tracking system.
Manages user online/offline status and presence updates.
"""

from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timedelta
import json
import asyncio

from ...core.logging import get_logger
from ...infrastructure.cache.redis_client import get_redis_client

logger = get_logger(__name__)


class PresenceManager:
    """
    Manages user presence (online/offline status) for WebSocket connections.
    Uses Redis for distributed presence tracking across multiple servers.
    """
    
    def __init__(self, redis_client=None):
        self.redis = redis_client
        self.ttl = 30  # seconds - presence expires after this time
        self.heartbeat_interval = 10  # seconds - how often to refresh presence
        self._presence_tasks: Dict[str, asyncio.Task] = {}
        self._local_presence: Dict[str, Dict[str, Any]] = {}  # Fallback for no Redis
        
    async def _ensure_redis(self):
        """Ensure Redis client is initialized."""
        if self.redis is None:
            try:
                self.redis = await get_redis_client()
            except Exception as e:
                logger.warning(
                    "Failed to get Redis client for presence tracking",
                    error=str(e)
                )
    
    async def update_presence(
        self,
        user_id: str,
        tenant_id: str,
        status: str = "online",
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Update user presence status.
        
        Args:
            user_id: User identifier
            tenant_id: Tenant identifier
            status: Presence status (online, away, busy, offline)
            metadata: Optional additional data (e.g., device info)
            
        Returns:
            True if update successful
        """
        try:
            key = f"presence:{tenant_id}:{user_id}"
            
            presence_data = {
                "user_id": user_id,
                "tenant_id": tenant_id,
                "status": status,
                "last_seen": datetime.utcnow().isoformat(),
                "metadata": metadata or {}
            }
            
            # Try Redis first
            await self._ensure_redis()
            if self.redis:
                # Set presence with TTL
                await self.redis.setex(
                    key, self.ttl, json.dumps(presence_data)
                )
                
                # Publish presence update for real-time notifications
                await self.redis.publish(
                    f"presence:{tenant_id}",
                    json.dumps({
                        "user_id": user_id,
                        "status": status,
                        "timestamp": presence_data["last_seen"]
                    })
                )
                
                logger.debug(
                    "Updated presence in Redis",
                    user_id=user_id,
                    tenant_id=tenant_id,
                    status=status
                )
            else:
                # Fallback to local storage
                self._local_presence[key] = presence_data
                logger.debug(
                    "Updated presence locally",
                    user_id=user_id,
                    tenant_id=tenant_id,
                    status=status
                )
            
            return True
            
        except Exception as e:
            logger.error(
                "Failed to update presence",
                error=str(e),
                user_id=user_id,
                tenant_id=tenant_id
            )
            return False
    
    async def get_user_presence(
        self,
        user_id: str,
        tenant_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get user presence information.
        
        Args:
            user_id: User identifier
            tenant_id: Tenant identifier
            
        Returns:
            Presence data or None if not found/expired
        """
        try:
            key = f"presence:{tenant_id}:{user_id}"
            
            # Try Redis first
            await self._ensure_redis()
            if self.redis:
                data = await self.redis.get(key)
                if data:
                    return json.loads(data)
            else:
                # Check local storage
                presence = self._local_presence.get(key)
                if presence:
                    # Check if expired
                    last_seen = datetime.fromisoformat(presence["last_seen"])
                    if (datetime.utcnow() - last_seen).total_seconds() < self.ttl:
                        return presence
                    else:
                        # Expired, remove it
                        self._local_presence.pop(key, None)
            
            return None
            
        except Exception as e:
            logger.error(
                "Failed to get user presence",
                error=str(e),
                user_id=user_id,
                tenant_id=tenant_id
            )
            return None
    
    async def get_online_users(
        self,
        tenant_id: str,
        include_away: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Get list of online users in a tenant.
        
        Args:
            tenant_id: Tenant identifier
            include_away: Include users with "away" status
            
        Returns:
            List of online user presence data
        """
        try:
            online_users = []
            
            # Try Redis first
            await self._ensure_redis()
            if self.redis:
                pattern = f"presence:{tenant_id}:*"
                keys = await self.redis.keys(pattern)
                
                for key in keys:
                    data = await self.redis.get(key)
                    if data:
                        presence = json.loads(data)
                        if presence["status"] == "online" or (include_away and presence["status"] == "away"):
                            online_users.append(presence)
            else:
                # Use local storage
                now = datetime.utcnow()
                for key, presence in list(self._local_presence.items()):
                    if key.startswith(f"presence:{tenant_id}:"):
                        # Check if expired
                        last_seen = datetime.fromisoformat(presence["last_seen"])
                        if (now - last_seen).total_seconds() < self.ttl:
                            if presence["status"] == "online" or (include_away and presence["status"] == "away"):
                                online_users.append(presence)
                        else:
                            # Expired, remove it
                            self._local_presence.pop(key, None)
            
            return online_users
            
        except Exception as e:
            logger.error(
                "Failed to get online users",
                error=str(e),
                tenant_id=tenant_id
            )
            return []
    
    async def remove_presence(self, user_id: str, tenant_id: str):
        """
        Remove user presence (mark as offline).
        
        Args:
            user_id: User identifier
            tenant_id: Tenant identifier
        """
        try:
            key = f"presence:{tenant_id}:{user_id}"
            
            # Update to offline status first
            await self.update_presence(user_id, tenant_id, "offline")
            
            # Then remove from storage
            await self._ensure_redis()
            if self.redis:
                await self.redis.delete(key)
            else:
                self._local_presence.pop(key, None)
            
            logger.debug(
                "Removed user presence",
                user_id=user_id,
                tenant_id=tenant_id
            )
            
        except Exception as e:
            logger.error(
                "Failed to remove presence",
                error=str(e),
                user_id=user_id,
                tenant_id=tenant_id
            )
    
    async def start_heartbeat(
        self,
        user_id: str,
        tenant_id: str,
        connection_id: str
    ):
        """
        Start periodic heartbeat to maintain presence.
        
        Args:
            user_id: User identifier
            tenant_id: Tenant identifier
            connection_id: Connection identifier for tracking
        """
        # Cancel any existing heartbeat for this connection
        if connection_id in self._presence_tasks:
            self._presence_tasks[connection_id].cancel()
        
        # Create heartbeat task
        task = asyncio.create_task(
            self._heartbeat_loop(user_id, tenant_id, connection_id)
        )
        self._presence_tasks[connection_id] = task
        
        logger.debug(
            "Started presence heartbeat",
            user_id=user_id,
            tenant_id=tenant_id,
            connection_id=connection_id
        )
    
    async def stop_heartbeat(self, connection_id: str):
        """
        Stop presence heartbeat for a connection.
        
        Args:
            connection_id: Connection identifier
        """
        if connection_id in self._presence_tasks:
            self._presence_tasks[connection_id].cancel()
            del self._presence_tasks[connection_id]
            
            logger.debug(
                "Stopped presence heartbeat",
                connection_id=connection_id
            )
    
    async def _heartbeat_loop(
        self,
        user_id: str,
        tenant_id: str,
        connection_id: str
    ):
        """
        Heartbeat loop to maintain presence.
        
        Args:
            user_id: User identifier
            tenant_id: Tenant identifier
            connection_id: Connection identifier
        """
        try:
            while True:
                # Update presence
                await self.update_presence(user_id, tenant_id, "online")
                
                # Wait for next heartbeat
                await asyncio.sleep(self.heartbeat_interval)
                
        except asyncio.CancelledError:
            logger.debug(
                "Heartbeat loop cancelled",
                user_id=user_id,
                connection_id=connection_id
            )
        except Exception as e:
            logger.error(
                "Error in heartbeat loop",
                error=str(e),
                user_id=user_id,
                connection_id=connection_id
            )
    
    async def subscribe_to_presence_updates(
        self,
        tenant_id: str,
        callback: callable
    ):
        """
        Subscribe to presence updates for a tenant.
        
        Args:
            tenant_id: Tenant identifier
            callback: Async function to call with presence updates
        """
        try:
            await self._ensure_redis()
            if self.redis:
                # Create pub/sub connection
                pubsub = self.redis.pubsub()
                await pubsub.subscribe(f"presence:{tenant_id}")
                
                # Listen for messages
                async for message in pubsub.listen():
                    if message["type"] == "message":
                        try:
                            data = json.loads(message["data"])
                            await callback(data)
                        except Exception as e:
                            logger.error(
                                "Error processing presence update",
                                error=str(e)
                            )
            else:
                logger.warning(
                    "Cannot subscribe to presence updates without Redis",
                    tenant_id=tenant_id
                )
                
        except Exception as e:
            logger.error(
                "Failed to subscribe to presence updates",
                error=str(e),
                tenant_id=tenant_id
            )
    
    async def get_presence_summary(self, tenant_id: str) -> Dict[str, int]:
        """
        Get summary of presence states in a tenant.
        
        Args:
            tenant_id: Tenant identifier
            
        Returns:
            Dictionary with counts by status
        """
        try:
            summary = {
                "online": 0,
                "away": 0,
                "busy": 0,
                "offline": 0
            }
            
            await self._ensure_redis()
            if self.redis:
                pattern = f"presence:{tenant_id}:*"
                keys = await self.redis.keys(pattern)
                
                for key in keys:
                    data = await self.redis.get(key)
                    if data:
                        presence = json.loads(data)
                        status = presence.get("status", "offline")
                        if status in summary:
                            summary[status] += 1
            else:
                # Use local storage
                now = datetime.utcnow()
                for key, presence in list(self._local_presence.items()):
                    if key.startswith(f"presence:{tenant_id}:"):
                        # Check if expired
                        last_seen = datetime.fromisoformat(presence["last_seen"])
                        if (now - last_seen).total_seconds() < self.ttl:
                            status = presence.get("status", "offline")
                            if status in summary:
                                summary[status] += 1
            
            return summary
            
        except Exception as e:
            logger.error(
                "Failed to get presence summary",
                error=str(e),
                tenant_id=tenant_id
            )
            return {"online": 0, "away": 0, "busy": 0, "offline": 0}
    
    async def cleanup_expired_presence(self):
        """
        Clean up expired presence entries (for local storage).
        Called periodically by a background task.
        """
        if not self._local_presence:
            return
        
        now = datetime.utcnow()
        expired_keys = []
        
        for key, presence in self._local_presence.items():
            last_seen = datetime.fromisoformat(presence["last_seen"])
            if (now - last_seen).total_seconds() > self.ttl:
                expired_keys.append(key)
        
        for key in expired_keys:
            self._local_presence.pop(key, None)
        
        if expired_keys:
            logger.debug(
                "Cleaned up expired presence entries",
                count=len(expired_keys)
            )
    
    async def shutdown(self):
        """
        Shutdown presence manager and clean up resources.
        """
        # Cancel all heartbeat tasks
        for task in self._presence_tasks.values():
            task.cancel()
        
        # Wait for cancellation
        if self._presence_tasks:
            await asyncio.gather(
                *self._presence_tasks.values(),
                return_exceptions=True
            )
        
        self._presence_tasks.clear()
        self._local_presence.clear()
        
        logger.info("Presence manager shutdown complete")


# Global instance
_presence_manager: Optional[PresenceManager] = None


def get_presence_manager() -> PresenceManager:
    """Get singleton presence manager."""
    global _presence_manager
    if _presence_manager is None:
        _presence_manager = PresenceManager()
    return _presence_manager