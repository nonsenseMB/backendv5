"""
WebSocket connection management module.
Handles connection lifecycle, state management, and message routing.
"""

from typing import Dict, Set, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID, uuid4
import asyncio
import json

from fastapi import WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from ...infrastructure.cache import get_redis_client
from ...core.logging import get_logger
from ...core.logging.auth_audit import AuthAuditService, AuthAuditEvent
from ...infrastructure.database.session import get_async_session

logger = get_logger(__name__)


@dataclass
class WebSocketConnection:
    """Represents an active WebSocket connection."""
    id: str
    websocket: WebSocket
    user_id: str
    tenant_id: str
    session_id: str
    device_id: Optional[str] = None
    connected_at: datetime = field(default_factory=datetime.utcnow)
    last_activity: datetime = field(default_factory=datetime.utcnow)
    
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


@dataclass
class ConnectionMetadata:
    """Metadata for a WebSocket connection."""
    user_id: str
    tenant_id: str
    session_id: str
    channels: Set[str] = field(default_factory=set)
    subscriptions: Set[str] = field(default_factory=set)
    permissions: Optional[Set[str]] = None
    rate_limit_state: Dict[str, int] = field(default_factory=dict)


class ConnectionManager:
    """
    Manages WebSocket connections and provides message routing.
    Supports multi-tenant, multi-device connections with Redis-backed state.
    """
    
    def __init__(self):
        # Local connection storage
        self._connections: Dict[str, WebSocketConnection] = {}
        self._user_connections: Dict[str, Set[str]] = {}
        self._metadata: Dict[str, ConnectionMetadata] = {}
        self._tenant_connections: Dict[str, Set[str]] = {}
        
        # Channel subscriptions
        self._channel_subscribers: Dict[str, Set[str]] = {}
        
        # Background tasks
        self._background_tasks: Set[asyncio.Task] = set()
        
        # Redis client will be initialized on first use
        self._redis = None
        
        # Connection limits
        self.max_connections_per_user = 10
        self.max_connections_per_tenant = 1000
    
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
            ConnectionError: If connection limits are exceeded
        """
        connection_id = str(uuid4())
        
        # Check connection limits
        await self._check_connection_limits(user_id, tenant_id)
        
        # Create connection object
        connection = WebSocketConnection(
            id=connection_id,
            websocket=websocket,
            user_id=user_id,
            tenant_id=tenant_id,
            session_id=session_id,
            device_id=device_id
        )
        
        # Store connection
        self._connections[connection_id] = connection
        
        # Track by user
        if user_id not in self._user_connections:
            self._user_connections[user_id] = set()
        self._user_connections[user_id].add(connection_id)
        
        # Track by tenant
        if tenant_id not in self._tenant_connections:
            self._tenant_connections[tenant_id] = set()
        self._tenant_connections[tenant_id].add(connection_id)
        
        # Store metadata
        self._metadata[connection_id] = ConnectionMetadata(
            user_id=user_id,
            tenant_id=tenant_id,
            session_id=session_id
        )
        
        # Publish connection event to Redis
        await self._publish_connection_event("connect", connection)
        
        # Log connection
        await self._log_connection_event(
            AuthAuditEvent.SESSION_CREATED,
            connection
        )
        
        logger.info(
            "WebSocket connected",
            connection_id=connection_id,
            user_id=user_id,
            tenant_id=tenant_id,
            device_id=device_id
        )
        
        return connection
    
    async def disconnect(self, connection_id: str):
        """
        Remove a WebSocket connection and clean up resources.
        
        Args:
            connection_id: Connection identifier
        """
        connection = self._connections.get(connection_id)
        if not connection:
            return
        
        # Remove from user connections
        user_connections = self._user_connections.get(connection.user_id, set())
        user_connections.discard(connection_id)
        if not user_connections:
            self._user_connections.pop(connection.user_id, None)
        
        # Remove from tenant connections
        tenant_connections = self._tenant_connections.get(connection.tenant_id, set())
        tenant_connections.discard(connection_id)
        if not tenant_connections:
            self._tenant_connections.pop(connection.tenant_id, None)
        
        # Remove from channels
        metadata = self._metadata.get(connection_id)
        if metadata:
            for channel in metadata.channels:
                channel_subs = self._channel_subscribers.get(channel, set())
                channel_subs.discard(connection_id)
                if not channel_subs:
                    self._channel_subscribers.pop(channel, None)
        
        # Clean up metadata
        self._metadata.pop(connection_id, None)
        
        # Remove connection
        self._connections.pop(connection_id, None)
        
        # Publish disconnection event
        await self._publish_connection_event("disconnect", connection)
        
        # Log disconnection
        await self._log_connection_event(
            AuthAuditEvent.SESSION_TERMINATED,
            connection
        )
        
        logger.info(
            "WebSocket disconnected",
            connection_id=connection_id,
            user_id=connection.user_id
        )
    
    async def join_channel(
        self,
        connection_id: str,
        channel: str
    ) -> bool:
        """
        Subscribe a connection to a channel.
        
        Args:
            connection_id: Connection identifier
            channel: Channel name (e.g., "team:123", "conversation:456")
            
        Returns:
            True if joined successfully, False otherwise
        """
        metadata = self._metadata.get(connection_id)
        if not metadata:
            return False
        
        # Verify channel access (implement based on your permission system)
        if not await self._verify_channel_access(
            metadata.user_id,
            metadata.tenant_id,
            channel
        ):
            logger.warning(
                "Channel access denied",
                user_id=metadata.user_id,
                channel=channel
            )
            return False
        
        # Add to channel
        metadata.channels.add(channel)
        
        # Track channel subscribers
        if channel not in self._channel_subscribers:
            self._channel_subscribers[channel] = set()
        self._channel_subscribers[channel].add(connection_id)
        
        # Publish to Redis for distributed tracking
        await self._redis_add_channel_member(channel, connection_id)
        
        logger.debug(
            "Joined channel",
            connection_id=connection_id,
            channel=channel
        )
        
        return True
    
    async def leave_channel(
        self,
        connection_id: str,
        channel: str
    ):
        """Remove a connection from a channel."""
        metadata = self._metadata.get(connection_id)
        if not metadata:
            return
        
        # Remove from channel
        metadata.channels.discard(channel)
        
        # Update channel subscribers
        if channel in self._channel_subscribers:
            self._channel_subscribers[channel].discard(connection_id)
            if not self._channel_subscribers[channel]:
                self._channel_subscribers.pop(channel, None)
        
        # Remove from Redis
        await self._redis_remove_channel_member(channel, connection_id)
        
        logger.debug(
            "Left channel",
            connection_id=connection_id,
            channel=channel
        )
    
    async def send_to_connection(
        self,
        connection_id: str,
        message: Dict
    ):
        """Send a message to a specific connection."""
        connection = self._connections.get(connection_id)
        if not connection or not connection.is_connected:
            return
        
        try:
            await connection.websocket.send_json(message)
            connection.update_activity()
        except WebSocketDisconnect:
            await self.disconnect(connection_id)
        except Exception as e:
            logger.error(
                "Failed to send message",
                connection_id=connection_id,
                error=str(e)
            )
            await self.disconnect(connection_id)
    
    async def send_to_user(
        self,
        user_id: str,
        message: Dict,
        exclude_connection: Optional[str] = None
    ):
        """Send a message to all connections of a user."""
        connection_ids = self._user_connections.get(user_id, set()).copy()
        
        for conn_id in connection_ids:
            if conn_id != exclude_connection:
                await self.send_to_connection(conn_id, message)
    
    async def send_to_channel(
        self,
        channel: str,
        message: Dict,
        exclude_connection: Optional[str] = None
    ):
        """Send a message to all connections in a channel."""
        # Get local subscribers
        local_subscribers = self._channel_subscribers.get(channel, set()).copy()
        
        # Send to local connections
        for conn_id in local_subscribers:
            if conn_id != exclude_connection:
                await self.send_to_connection(conn_id, message)
        
        # Publish to Redis for distributed delivery
        await self._redis_publish_channel_message(channel, message, exclude_connection)
    
    async def broadcast_to_tenant(
        self,
        tenant_id: str,
        message: Dict,
        exclude_connection: Optional[str] = None
    ):
        """Broadcast a message to all connections in a tenant."""
        connection_ids = self._tenant_connections.get(tenant_id, set()).copy()
        
        for conn_id in connection_ids:
            if conn_id != exclude_connection:
                await self.send_to_connection(conn_id, message)
    
    def get_connection(self, connection_id: str) -> Optional[WebSocketConnection]:
        """Get a connection by ID."""
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
        This is a placeholder - implement based on your permission system.
        """
        # Parse channel type and ID
        if ":" not in channel:
            return False
        
        channel_type, channel_id = channel.split(":", 1)
        
        # Implement channel-specific access checks
        if channel_type == "tenant":
            # User must belong to the tenant
            return channel_id == tenant_id
        elif channel_type in ["team", "conversation", "document"]:
            # Check resource-specific permissions
            # This would integrate with your permission system
            return True  # Placeholder
        else:
            # Unknown channel type
            return False
    
    async def _get_redis(self):
        """Get Redis client (lazy initialization)."""
        if self._redis is None:
            self._redis = await get_redis_client()
        return self._redis
    
    async def _publish_connection_event(self, event: str, connection: WebSocketConnection):
        """Publish connection event to Redis for distributed tracking."""
        try:
            redis = await self._get_redis()
            
            event_data = {
                "event": event,
                "connection_id": connection.id,
                "user_id": connection.user_id,
                "tenant_id": connection.tenant_id,
                "session_id": connection.session_id,
                "device_id": connection.device_id,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Publish to tenant channel
            await redis.client.publish(
                f"ws:tenant:{connection.tenant_id}:events",
                json.dumps(event_data)
            )
            
        except Exception as e:
            logger.error(
                "Failed to publish connection event",
                error=str(e),
                event=event
            )
    
    async def _redis_add_channel_member(self, channel: str, connection_id: str):
        """Add channel member in Redis."""
        try:
            redis = await self._get_redis()
            await redis.client.sadd(f"ws:channel:{channel}:members", connection_id)
            await redis.client.expire(f"ws:channel:{channel}:members", 3600)  # 1 hour TTL
        except Exception as e:
            logger.error(
                "Failed to add channel member in Redis",
                error=str(e),
                channel=channel
            )
    
    async def _redis_remove_channel_member(self, channel: str, connection_id: str):
        """Remove channel member from Redis."""
        try:
            redis = await self._get_redis()
            await redis.client.srem(f"ws:channel:{channel}:members", connection_id)
        except Exception as e:
            logger.error(
                "Failed to remove channel member from Redis",
                error=str(e),
                channel=channel
            )
    
    async def _redis_publish_channel_message(
        self,
        channel: str,
        message: Dict,
        exclude_connection: Optional[str] = None
    ):
        """Publish channel message to Redis for distributed delivery."""
        try:
            redis = await self._get_redis()
            
            message_data = {
                "channel": channel,
                "message": message,
                "exclude_connection": exclude_connection,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            await redis.client.publish(
                f"ws:channel:{channel}:messages",
                json.dumps(message_data)
            )
            
        except Exception as e:
            logger.error(
                "Failed to publish channel message to Redis",
                error=str(e),
                channel=channel
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
                        "connection_type": "websocket"
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
_connection_manager: Optional[ConnectionManager] = None


def get_connection_manager() -> ConnectionManager:
    """Get singleton connection manager instance."""
    global _connection_manager
    if _connection_manager is None:
        _connection_manager = ConnectionManager()
    return _connection_manager