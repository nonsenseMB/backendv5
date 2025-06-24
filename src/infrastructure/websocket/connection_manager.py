"""
Enhanced WebSocket connection manager with distributed state support.
Manages connection lifecycle, channels, and Redis-based synchronization.
"""

from typing import Dict, Set, Optional, List, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from uuid import UUID, uuid4
import asyncio
import json
import os

from fastapi import WebSocket
from starlette.websockets import WebSocketState

from ...infrastructure.cache import get_redis_client
from ...core.logging import get_logger
from ...core.logging.auth_audit import AuthAuditService, AuthAuditEvent
from ...infrastructure.database.session import get_async_session
from .connection_state import (
    ConnectionStatus,
    ConnectionMetadata,
    ConnectionStats,
    DistributedConnectionInfo,
    RateLimitAction
)
from .presence import get_presence_manager

logger = get_logger(__name__)


@dataclass
class WebSocketConnection:
    """Enhanced WebSocket connection with state tracking."""
    id: str
    websocket: WebSocket
    user_id: str
    tenant_id: str
    session_id: str
    device_id: Optional[str] = None
    connected_at: datetime = field(default_factory=datetime.utcnow)
    last_activity: datetime = field(default_factory=datetime.utcnow)
    status: ConnectionStatus = ConnectionStatus.CONNECTED
    stats: ConnectionStats = field(default_factory=ConnectionStats)
    
    def update_activity(self):
        """Update last activity timestamp."""
        self.last_activity = datetime.utcnow()
    
    @property
    def is_connected(self) -> bool:
        """Check if WebSocket is still connected."""
        return (
            self.websocket.client_state == WebSocketState.CONNECTED and
            self.websocket.application_state == WebSocketState.CONNECTED
        )
    
    @property
    def connection_duration(self) -> timedelta:
        """Get connection duration."""
        return datetime.utcnow() - self.connected_at


class EnhancedConnectionManager:
    """
    Enhanced connection manager with distributed state support.
    Manages WebSocket connections across multiple servers using Redis.
    """
    
    def __init__(self, server_id: Optional[str] = None):
        # Server identification for distributed setup
        self.server_id = server_id or os.getenv("SERVER_ID", str(uuid4()))
        
        # Local connection storage
        self._connections: Dict[str, WebSocketConnection] = {}
        self._metadata: Dict[str, ConnectionMetadata] = {}
        self._user_connections: Dict[str, Set[str]] = {}
        self._tenant_connections: Dict[str, Set[str]] = {}
        
        # Configuration
        self.max_connections_per_user = 5
        self.max_connections_per_tenant = 1000
        self.connection_timeout = 3600  # 1 hour
        self.heartbeat_interval = 30    # 30 seconds
        
        # Background tasks
        self._cleanup_task: Optional[asyncio.Task] = None
        self._sync_task: Optional[asyncio.Task] = None
    
    async def initialize(self):
        """Initialize the connection manager."""
        # Start background tasks
        self._cleanup_task = asyncio.create_task(self._cleanup_inactive_connections())
        self._sync_task = asyncio.create_task(self._sync_distributed_state())
        
        logger.info(
            "Connection manager initialized",
            server_id=self.server_id
        )
    
    async def shutdown(self):
        """Shutdown the connection manager."""
        # Cancel background tasks
        if self._cleanup_task:
            self._cleanup_task.cancel()
        if self._sync_task:
            self._sync_task.cancel()
        
        # Close all connections
        for connection in list(self._connections.values()):
            await self.disconnect(connection.id, reason="Server shutdown")
        
        logger.info("Connection manager shutdown")
    
    async def connect(
        self,
        websocket: WebSocket,
        user_id: str,
        tenant_id: str,
        session_id: str,
        device_id: Optional[str] = None
    ) -> WebSocketConnection:
        """
        Register a new WebSocket connection.
        
        Args:
            websocket: The WebSocket instance
            user_id: User identifier
            tenant_id: Tenant identifier
            session_id: Session identifier
            device_id: Optional device identifier
            
        Returns:
            WebSocketConnection instance
            
        Raises:
            ConnectionError: If connection limits exceeded
        """
        # Check connection limits
        await self._check_connection_limits(user_id, tenant_id)
        
        # Create connection
        connection_id = str(uuid4())
        connection = WebSocketConnection(
            id=connection_id,
            websocket=websocket,
            user_id=user_id,
            tenant_id=tenant_id,
            session_id=session_id,
            device_id=device_id,
            status=ConnectionStatus.AUTHENTICATED
        )
        
        # Store connection
        self._connections[connection_id] = connection
        
        # Update user connections
        if user_id not in self._user_connections:
            self._user_connections[user_id] = set()
        self._user_connections[user_id].add(connection_id)
        
        # Update tenant connections
        if tenant_id not in self._tenant_connections:
            self._tenant_connections[tenant_id] = set()
        self._tenant_connections[tenant_id].add(connection_id)
        
        # Create metadata
        self._metadata[connection_id] = ConnectionMetadata(
            user_id=user_id,
            tenant_id=tenant_id,
            session_id=session_id
        )
        
        # Join default channels
        await self.join_channel(connection_id, f"user:{user_id}")
        await self.join_channel(connection_id, f"tenant:{tenant_id}")
        
        # Publish to Redis for distributed tracking
        await self._publish_connection_event("connect", connection)
        
        # Store in Redis
        await self._store_connection_info(connection)
        
        # Log connection event
        await self._log_connection_event(
            AuthAuditEvent.LOGIN_SUCCESS,
            connection
        )
        
        # Start presence tracking
        presence_manager = get_presence_manager()
        await presence_manager.update_presence(user_id, tenant_id, "online", {
            "device_id": device_id,
            "connection_id": connection_id,
            "session_id": session_id
        })
        await presence_manager.start_heartbeat(user_id, tenant_id, connection_id)
        
        # Broadcast presence update to tenant
        await self._broadcast_presence_update(user_id, tenant_id, "online")
        
        logger.info(
            "WebSocket connected",
            connection_id=connection_id,
            user_id=user_id,
            tenant_id=tenant_id,
            device_id=device_id
        )
        
        return connection
    
    async def disconnect(
        self,
        connection_id: str,
        reason: str = "Normal closure"
    ):
        """
        Disconnect and cleanup a WebSocket connection.
        
        Args:
            connection_id: Connection identifier
            reason: Disconnect reason
        """
        connection = self._connections.get(connection_id)
        if not connection:
            return
        
        # Update status
        connection.status = ConnectionStatus.DISCONNECTING
        
        # Leave all channels
        metadata = self._metadata.get(connection_id)
        if metadata:
            for channel in list(metadata.channels):
                await self.leave_channel(connection_id, channel)
        
        # Close WebSocket
        if connection.is_connected:
            try:
                await connection.websocket.close(code=1000, reason=reason)
            except Exception as e:
                logger.warning(
                    "Error closing WebSocket",
                    error=str(e),
                    connection_id=connection_id
                )
        
        # Remove from user connections
        if connection.user_id in self._user_connections:
            self._user_connections[connection.user_id].discard(connection_id)
            if not self._user_connections[connection.user_id]:
                del self._user_connections[connection.user_id]
        
        # Remove from tenant connections
        if connection.tenant_id in self._tenant_connections:
            self._tenant_connections[connection.tenant_id].discard(connection_id)
            if not self._tenant_connections[connection.tenant_id]:
                del self._tenant_connections[connection.tenant_id]
        
        # Remove from Redis
        await self._remove_connection_info(connection_id)
        
        # Publish disconnect event
        await self._publish_connection_event("disconnect", connection)
        
        # Log disconnection
        await self._log_connection_event(
            AuthAuditEvent.LOGOUT,
            connection
        )
        
        # Stop presence tracking
        presence_manager = get_presence_manager()
        await presence_manager.stop_heartbeat(connection_id)
        
        # Check if user has other connections
        user_has_other_connections = (
            connection.user_id in self._user_connections and
            len(self._user_connections[connection.user_id]) > 0
        )
        
        # Update presence if no other connections
        if not user_has_other_connections:
            await presence_manager.remove_presence(connection.user_id, connection.tenant_id)
            await self._broadcast_presence_update(connection.user_id, connection.tenant_id, "offline")
        
        # Cleanup
        del self._connections[connection_id]
        if connection_id in self._metadata:
            del self._metadata[connection_id]
        
        logger.info(
            "WebSocket disconnected",
            connection_id=connection_id,
            reason=reason
        )
    
    async def join_channel(
        self, connection_id: str, channel: str
    ) -> bool:
        """
        Join a channel for receiving broadcasts.
        
        Args:
            connection_id: Connection identifier
            channel: Channel name
            
        Returns:
            True if joined successfully
        """
        metadata = self._metadata.get(connection_id)
        if not metadata:
            return False
        
        # Verify channel access
        if not await self._verify_channel_access(
            metadata.user_id, metadata.tenant_id, channel
        ):
            logger.warning(
                "Channel access denied",
                connection_id=connection_id,
                channel=channel
            )
            return False
        
        # Add to local tracking
        metadata.add_channel(channel)
        
        # Add to Redis for distributed messaging
        redis = await get_redis_client()
        await redis.sadd(f"channel:{channel}:connections", connection_id)
        await redis.sadd(f"connection:{connection_id}:channels", channel)
        
        # Update distributed state
        connection = self._connections.get(connection_id)
        if connection:
            await self._update_distributed_channels(connection_id, metadata.channels)
        
        logger.debug(
            "Joined channel",
            connection_id=connection_id,
            channel=channel
        )
        
        return True
    
    async def leave_channel(
        self, connection_id: str, channel: str
    ):
        """
        Leave a channel.
        
        Args:
            connection_id: Connection identifier
            channel: Channel name
        """
        metadata = self._metadata.get(connection_id)
        if not metadata:
            return
        
        # Remove from local tracking
        metadata.remove_channel(channel)
        
        # Remove from Redis
        redis = await get_redis_client()
        await redis.srem(f"channel:{channel}:connections", connection_id)
        await redis.srem(f"connection:{connection_id}:channels", channel)
        
        # Update distributed state
        await self._update_distributed_channels(connection_id, metadata.channels)
        
        logger.debug(
            "Left channel",
            connection_id=connection_id,
            channel=channel
        )
    
    async def subscribe_resource(
        self, connection_id: str, resource: str
    ) -> bool:
        """
        Subscribe to resource updates.
        
        Args:
            connection_id: Connection identifier
            resource: Resource identifier (e.g., "conversation:123")
            
        Returns:
            True if subscribed successfully
        """
        metadata = self._metadata.get(connection_id)
        if not metadata:
            return False
        
        # Add subscription
        metadata.add_subscription(resource)
        
        # Store in Redis
        redis = await get_redis_client()
        await redis.sadd(f"resource:{resource}:subscribers", connection_id)
        await redis.sadd(f"connection:{connection_id}:subscriptions", resource)
        
        logger.debug(
            "Subscribed to resource",
            connection_id=connection_id,
            resource=resource
        )
        
        return True
    
    async def unsubscribe_resource(
        self, connection_id: str, resource: str
    ):
        """
        Unsubscribe from resource updates.
        
        Args:
            connection_id: Connection identifier
            resource: Resource identifier
        """
        metadata = self._metadata.get(connection_id)
        if not metadata:
            return
        
        # Remove subscription
        metadata.remove_subscription(resource)
        
        # Remove from Redis
        redis = await get_redis_client()
        await redis.srem(f"resource:{resource}:subscribers", connection_id)
        await redis.srem(f"connection:{connection_id}:subscriptions", resource)
        
        logger.debug(
            "Unsubscribed from resource",
            connection_id=connection_id,
            resource=resource
        )
    
    async def send_to_connection(
        self, connection_id: str, message: Dict
    ) -> bool:
        """
        Send message to specific connection.
        
        Args:
            connection_id: Connection identifier
            message: Message data
            
        Returns:
            True if sent successfully
        """
        connection = self._connections.get(connection_id)
        if not connection or not connection.is_connected:
            return False
        
        try:
            await connection.websocket.send_json(message)
            connection.stats.record_message_sent(len(json.dumps(message)))
            connection.update_activity()
            return True
        except Exception as e:
            logger.error(
                "Failed to send message",
                error=str(e),
                connection_id=connection_id
            )
            connection.stats.record_error(str(e))
            return False
    
    async def broadcast_to_channel(
        self,
        channel: str,
        message: Dict,
        exclude_connection: Optional[str] = None
    ):
        """
        Broadcast message to all connections in a channel.
        
        Args:
            channel: Channel name
            message: Message data
            exclude_connection: Connection to exclude from broadcast
        """
        # Get connections from Redis
        redis = await get_redis_client()
        connection_ids = await redis.smembers(f"channel:{channel}:connections")
        
        # Send to local connections
        for conn_id in connection_ids:
            if conn_id != exclude_connection and conn_id in self._connections:
                await self.send_to_connection(conn_id, message)
        
        # Publish for other servers
        await self._publish_channel_message(channel, message, exclude_connection)
    
    async def broadcast_to_user(
        self,
        user_id: str,
        message: Dict,
        exclude_connection: Optional[str] = None
    ):
        """
        Broadcast message to all connections of a user.
        
        Args:
            user_id: User identifier
            message: Message data
            exclude_connection: Connection to exclude
        """
        connection_ids = self._user_connections.get(user_id, set()).copy()
        
        for conn_id in connection_ids:
            if conn_id != exclude_connection:
                await self.send_to_connection(conn_id, message)
    
    async def broadcast_to_tenant(
        self,
        tenant_id: str,
        message: Dict,
        exclude_connection: Optional[str] = None
    ):
        """
        Broadcast message to all connections in a tenant.
        
        Args:
            tenant_id: Tenant identifier
            message: Message data
            exclude_connection: Connection to exclude
        """
        await self.broadcast_to_channel(
            f"tenant:{tenant_id}",
            message,
            exclude_connection
        )
    
    def get_connection(self, connection_id: str) -> Optional[WebSocketConnection]:
        """Get connection by ID."""
        return self._connections.get(connection_id)
    
    def get_metadata(self, connection_id: str) -> Optional[ConnectionMetadata]:
        """Get connection metadata."""
        return self._metadata.get(connection_id)
    
    def get_user_connections(self, user_id: str) -> List[WebSocketConnection]:
        """Get all connections for a user."""
        connection_ids = self._user_connections.get(user_id, set())
        return [
            self._connections[conn_id] 
            for conn_id in connection_ids 
            if conn_id in self._connections
        ]
    
    def get_online_users(self, tenant_id: str) -> Set[str]:
        """Get set of online user IDs for a tenant."""
        online_users = set()
        for conn_id in self._tenant_connections.get(tenant_id, set()):
            if conn_id in self._connections:
                online_users.add(self._connections[conn_id].user_id)
        return online_users
    
    async def check_rate_limit(
        self, connection_id: str, action: RateLimitAction
    ) -> bool:
        """
        Check if action is rate limited.
        
        Args:
            connection_id: Connection identifier
            action: Action to check
            
        Returns:
            True if action is allowed
        """
        metadata = self._metadata.get(connection_id)
        if not metadata:
            return False
        
        return metadata.rate_limit.check_rate_limit(action)
    
    async def get_connection_stats(
        self, connection_id: str
    ) -> Optional[Dict]:
        """Get connection statistics."""
        connection = self._connections.get(connection_id)
        if not connection:
            return None
        
        return {
            **connection.stats.to_dict(),
            "connection_duration": connection.connection_duration.total_seconds(),
            "is_connected": connection.is_connected
        }
    
    async def get_distributed_connections(
        self, user_id: Optional[str] = None,
        tenant_id: Optional[str] = None
    ) -> List[DistributedConnectionInfo]:
        """
        Get all connections across all servers.
        
        Args:
            user_id: Filter by user ID
            tenant_id: Filter by tenant ID
            
        Returns:
            List of distributed connection info
        """
        redis = await get_redis_client()
        pattern = "connection:*:info"
        
        connections = []
        cursor = 0
        
        while True:
            cursor, keys = await redis.scan(
                cursor, match=pattern, count=100
            )
            
            for key in keys:
                data = await redis.hgetall(key)
                if data:
                    info = DistributedConnectionInfo.from_redis_hash(data)
                    
                    # Apply filters
                    if user_id and info.user_id != user_id:
                        continue
                    if tenant_id and info.tenant_id != tenant_id:
                        continue
                    
                    connections.append(info)
            
            if cursor == 0:
                break
        
        return connections
    
    # Private methods
    
    async def _check_connection_limits(self, user_id: str, tenant_id: str):
        """Check if connection limits are exceeded."""
        # Check user connection limit
        user_connections = len(self._user_connections.get(user_id, set()))
        if user_connections >= self.max_connections_per_user:
            raise ConnectionError(
                f"User connection limit exceeded ({self.max_connections_per_user})"
            )
        
        # Check tenant connection limit
        tenant_connections = len(self._tenant_connections.get(tenant_id, set()))
        if tenant_connections >= self.max_connections_per_tenant:
            raise ConnectionError(
                f"Tenant connection limit exceeded ({self.max_connections_per_tenant})"
            )
    
    async def _verify_channel_access(
        self,
        user_id: str,
        tenant_id: str,
        channel: str
    ) -> bool:
        """
        Verify if a user has access to a channel.
        Override this method to implement custom access control.
        """
        # Parse channel type and ID
        if ":" not in channel:
            return False
        
        channel_type, channel_id = channel.split(":", 1)
        
        # Basic access rules
        if channel_type == "user":
            # User can only join their own user channel
            return channel_id == user_id
        
        elif channel_type == "tenant":
            # User must belong to the tenant
            return channel_id == tenant_id
        
        elif channel_type == "conversation":
            # Check conversation membership through permission system
            try:
                async for db in get_async_session():
                    from ...core.auth.permissions import PermissionChecker
                    permission_checker = PermissionChecker(db)
                    has_access = await permission_checker.check_permission(
                        user_id=user_id,
                        tenant_id=tenant_id,
                        permission="conversation.read"
                    )
                    return has_access
            except Exception as e:
                logger.error(
                    "Failed to check conversation access",
                    error=str(e),
                    user_id=user_id,
                    conversation_id=channel_id
                )
                return False
        
        elif channel_type == "presence":
            # Presence channels are tenant-specific
            return channel_id == tenant_id
        
        # Default deny
        return False
    
    async def _store_connection_info(self, connection: WebSocketConnection):
        """Store connection info in Redis."""
        redis = await get_redis_client()
        
        info = DistributedConnectionInfo(
            connection_id=connection.id,
            server_id=self.server_id,
            user_id=connection.user_id,
            tenant_id=connection.tenant_id,
            session_id=connection.session_id,
            device_id=connection.device_id,
            connected_at=connection.connected_at,
            last_activity=connection.last_activity,
            status=connection.status,
            channels=self._metadata[connection.id].channels if connection.id in self._metadata else set()
        )
        
        # Store with TTL
        key = f"connection:{connection.id}:info"
        await redis.hset(key, mapping=info.to_redis_hash())
        await redis.expire(key, self.connection_timeout)
        
        # Add to user index
        await redis.sadd(f"user:{connection.user_id}:connections", connection.id)
        await redis.expire(f"user:{connection.user_id}:connections", self.connection_timeout)
        
        # Add to tenant index
        await redis.sadd(f"tenant:{connection.tenant_id}:connections", connection.id)
        await redis.expire(f"tenant:{connection.tenant_id}:connections", self.connection_timeout)
    
    async def _remove_connection_info(self, connection_id: str):
        """Remove connection info from Redis."""
        redis = await get_redis_client()
        
        # Get connection info
        data = await redis.hgetall(f"connection:{connection_id}:info")
        if data:
            # Remove from indexes
            await redis.srem(f"user:{data['user_id']}:connections", connection_id)
            await redis.srem(f"tenant:{data['tenant_id']}:connections", connection_id)
        
        # Remove connection info
        await redis.delete(f"connection:{connection_id}:info")
        
        # Remove channels
        await redis.delete(f"connection:{connection_id}:channels")
        
        # Remove subscriptions
        await redis.delete(f"connection:{connection_id}:subscriptions")
    
    async def _update_distributed_channels(
        self, connection_id: str, channels: Set[str]
    ):
        """Update channel list in distributed state."""
        redis = await get_redis_client()
        await redis.hset(
            f"connection:{connection_id}:info",
            "channels",
            ",".join(channels)
        )
    
    async def _publish_connection_event(
        self, event_type: str, connection: WebSocketConnection
    ):
        """Publish connection event for other servers."""
        redis = await get_redis_client()
        
        event_data = {
            "event": event_type,
            "connection_id": connection.id,
            "server_id": self.server_id,
            "user_id": connection.user_id,
            "tenant_id": connection.tenant_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await redis.publish(
            f"websocket:events:{connection.tenant_id}",
            json.dumps(event_data)
        )
    
    async def _publish_channel_message(
        self,
        channel: str,
        message: Dict,
        exclude_connection: Optional[str] = None
    ):
        """Publish channel message for other servers."""
        redis = await get_redis_client()
        
        message_data = {
            "channel": channel,
            "message": message,
            "exclude": exclude_connection,
            "server_id": self.server_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await redis.publish(
            f"websocket:channel:{channel}",
            json.dumps(message_data)
        )
    
    async def _broadcast_presence_update(
        self,
        user_id: str,
        tenant_id: str,
        status: str
    ):
        """
        Broadcast presence update to all tenant members.
        
        Args:
            user_id: User whose presence changed
            tenant_id: Tenant to broadcast to
            status: New presence status
        """
        message = {
            "type": "presence_update",
            "user_id": user_id,
            "status": status,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Broadcast to tenant channel
        await self.broadcast_to_channel(
            f"tenant:{tenant_id}",
            message,
            exclude_connection=None  # Send to all
        )
    
    async def get_online_users_with_presence(self, tenant_id: str) -> List[Dict[str, Any]]:
        """
        Get list of online users with presence data in a tenant.
        
        Args:
            tenant_id: Tenant identifier
            
        Returns:
            List of online user presence data
        """
        presence_manager = get_presence_manager()
        return await presence_manager.get_online_users(tenant_id)
    
    async def get_presence_summary(self, tenant_id: str) -> Dict[str, int]:
        """
        Get summary of presence states in a tenant.
        
        Args:
            tenant_id: Tenant identifier
            
        Returns:
            Dictionary with counts by status
        """
        presence_manager = get_presence_manager()
        return await presence_manager.get_presence_summary(tenant_id)
    
    async def update_user_presence(
        self,
        connection_id: str,
        status: str
    ) -> bool:
        """
        Update user presence status.
        
        Args:
            connection_id: Connection identifier
            status: New status (online, away, busy, offline)
            
        Returns:
            True if update successful
        """
        connection = self._connections.get(connection_id)
        if not connection:
            return False
        
        # Validate status
        valid_statuses = ["online", "away", "busy", "offline"]
        if status not in valid_statuses:
            logger.warning(
                "Invalid presence status",
                status=status,
                connection_id=connection_id
            )
            return False
        
        # Update presence
        presence_manager = get_presence_manager()
        success = await presence_manager.update_presence(
            connection.user_id,
            connection.tenant_id,
            status,
            {
                "device_id": connection.device_id,
                "connection_id": connection_id,
                "session_id": connection.session_id
            }
        )
        
        if success:
            # Broadcast update
            await self._broadcast_presence_update(
                connection.user_id,
                connection.tenant_id,
                status
            )
        
        return success
    
    async def _cleanup_inactive_connections(self):
        """Background task to cleanup inactive connections."""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute
                
                now = datetime.utcnow()
                inactive_timeout = timedelta(minutes=30)
                
                for connection in list(self._connections.values()):
                    # Check if connection is inactive
                    if now - connection.last_activity > inactive_timeout:
                        logger.info(
                            "Closing inactive connection",
                            connection_id=connection.id,
                            inactive_duration=(now - connection.last_activity).total_seconds()
                        )
                        await self.disconnect(connection.id, "Inactive timeout")
                    
                    # Send heartbeat
                    elif connection.is_connected:
                        await self.send_to_connection(
                            connection.id,
                            {"type": "ping", "timestamp": now.isoformat()}
                        )
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(
                    "Error in connection cleanup",
                    error=str(e),
                    exc_info=True
                )
    
    async def _sync_distributed_state(self):
        """Background task to sync distributed state."""
        while True:
            try:
                await asyncio.sleep(30)  # Sync every 30 seconds
                
                # Update activity timestamps in Redis
                redis = await get_redis_client()
                
                for connection in self._connections.values():
                    key = f"connection:{connection.id}:info"
                    await redis.hset(
                        key,
                        "last_activity",
                        connection.last_activity.isoformat()
                    )
                    await redis.expire(key, self.connection_timeout)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(
                    "Error syncing distributed state",
                    error=str(e),
                    exc_info=True
                )
    
    async def _log_connection_event(
        self,
        event_type: AuthAuditEvent,
        connection: WebSocketConnection
    ):
        """Log connection event to audit system."""
        try:
            async for db in get_async_session():
                audit_service = AuthAuditService(db)
                
                await audit_service.log_auth_event(
                    event_type=event_type,
                    user_id=UUID(connection.user_id),
                    tenant_id=UUID(connection.tenant_id),
                    session_id=UUID(connection.session_id),
                    action="websocket_connection",
                    details={
                        "connection_id": connection.id,
                        "device_id": connection.device_id,
                        "connection_type": "websocket",
                        "server_id": self.server_id
                    },
                    success=True
                )
                break
            
        except Exception as e:
            logger.error(
                "Failed to log connection event",
                error=str(e),
                event_type=event_type.value
            )


# Global connection manager instance
_connection_manager: Optional[EnhancedConnectionManager] = None


async def get_connection_manager() -> EnhancedConnectionManager:
    """Get singleton connection manager instance."""
    global _connection_manager
    if _connection_manager is None:
        _connection_manager = EnhancedConnectionManager()
        await _connection_manager.initialize()
    return _connection_manager