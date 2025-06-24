"""
WebSocket connection management facade.
Provides a simplified interface over the enhanced infrastructure connection manager.
"""

from typing import Dict, Set, Optional, List, Any
from datetime import datetime
from uuid import UUID, uuid4
import asyncio
import json

from fastapi import WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from ...infrastructure.websocket.connection_manager import (
    EnhancedConnectionManager,
    WebSocketConnection,
    get_connection_manager as get_enhanced_manager
)
from ...infrastructure.websocket.connection_state import (
    ConnectionMetadata,
    RateLimitAction
)
from ...core.logging import get_logger

logger = get_logger(__name__)


class ConnectionManager:
    """
    Facade for the enhanced WebSocket connection manager.
    Provides backward compatibility while delegating to the infrastructure layer.
    """
    
    def __init__(self):
        self._enhanced_manager: Optional[EnhancedConnectionManager] = None
        self._initialized = False
    
    async def _ensure_initialized(self):
        """Ensure the enhanced manager is initialized."""
        if not self._initialized:
            self._enhanced_manager = await get_enhanced_manager()
            self._initialized = True
    
    async def connect(
        self,
        websocket: WebSocket,
        user_id: str,
        tenant_id: str,
        session_id: str,
        device_id: Optional[str] = None
    ) -> WebSocketConnection:
        """Register a new WebSocket connection."""
        await self._ensure_initialized()
        return await self._enhanced_manager.connect(
            websocket, user_id, tenant_id, session_id, device_id
        )
    
    async def disconnect(
        self,
        connection_id: str,
        close_code: int = 1000,
        reason: str = "Normal closure"
    ):
        """Disconnect and cleanup a WebSocket connection."""
        await self._ensure_initialized()
        await self._enhanced_manager.disconnect(connection_id, reason)
    
    async def send_to_connection(
        self,
        connection_id: str,
        message: Dict[str, Any]
    ) -> bool:
        """Send message to specific connection."""
        await self._ensure_initialized()
        return await self._enhanced_manager.send_to_connection(connection_id, message)
    
    async def send_to_user(
        self,
        user_id: str,
        message: Dict[str, Any],
        exclude_connection: Optional[str] = None
    ):
        """Send message to all connections of a user."""
        await self._ensure_initialized()
        await self._enhanced_manager.broadcast_to_user(
            user_id, message, exclude_connection
        )
    
    async def send_to_tenant(
        self,
        tenant_id: str,
        message: Dict[str, Any],
        exclude_connection: Optional[str] = None
    ):
        """Send message to all connections in a tenant."""
        await self._ensure_initialized()
        await self._enhanced_manager.broadcast_to_tenant(
            tenant_id, message, exclude_connection
        )
    
    async def send_to_channel(
        self,
        channel: str,
        message: Dict[str, Any],
        exclude_connection: Optional[str] = None
    ):
        """Send message to all connections in a channel."""
        await self._ensure_initialized()
        await self._enhanced_manager.broadcast_to_channel(
            channel, message, exclude_connection
        )
    
    async def join_channel(
        self,
        connection_id: str,
        channel: str
    ) -> bool:
        """Add connection to a channel."""
        await self._ensure_initialized()
        return await self._enhanced_manager.join_channel(connection_id, channel)
    
    async def leave_channel(
        self,
        connection_id: str,
        channel: str
    ):
        """Remove connection from a channel."""
        await self._ensure_initialized()
        await self._enhanced_manager.leave_channel(connection_id, channel)
    
    async def subscribe_resource(
        self,
        connection_id: str,
        resource: str
    ) -> bool:
        """Subscribe to resource updates."""
        await self._ensure_initialized()
        return await self._enhanced_manager.subscribe_resource(connection_id, resource)
    
    async def unsubscribe_resource(
        self,
        connection_id: str,
        resource: str
    ):
        """Unsubscribe from resource updates."""
        await self._ensure_initialized()
        await self._enhanced_manager.unsubscribe_resource(connection_id, resource)
    
    def get_connection(self, connection_id: str) -> Optional[WebSocketConnection]:
        """Get connection by ID."""
        if not self._initialized:
            return None
        return self._enhanced_manager.get_connection(connection_id)
    
    def get_metadata(self, connection_id: str) -> Optional[ConnectionMetadata]:
        """Get connection metadata."""
        if not self._initialized:
            return None
        return self._enhanced_manager.get_metadata(connection_id)
    
    def get_user_connections(self, user_id: str) -> List[WebSocketConnection]:
        """Get all connections for a user."""
        if not self._initialized:
            return []
        return self._enhanced_manager.get_user_connections(user_id)
    
    def get_online_users(self, tenant_id: str) -> Set[str]:
        """Get set of online user IDs for a tenant."""
        if not self._initialized:
            return set()
        return self._enhanced_manager.get_online_users(tenant_id)
    
    async def check_rate_limit(
        self,
        connection_id: str,
        action: str
    ) -> bool:
        """Check if action is rate limited."""
        await self._ensure_initialized()
        
        # Convert string action to enum
        try:
            rate_limit_action = RateLimitAction(action)
        except ValueError:
            rate_limit_action = RateLimitAction.DEFAULT
        
        return await self._enhanced_manager.check_rate_limit(
            connection_id, rate_limit_action
        )
    
    # Compatibility properties
    @property
    def max_connections_per_user(self) -> int:
        """Get max connections per user."""
        if self._initialized:
            return self._enhanced_manager.max_connections_per_user
        return 10
    
    @max_connections_per_user.setter
    def max_connections_per_user(self, value: int):
        """Set max connections per user."""
        if self._initialized:
            self._enhanced_manager.max_connections_per_user = value
    
    @property
    def max_connections_per_tenant(self) -> int:
        """Get max connections per tenant."""
        if self._initialized:
            return self._enhanced_manager.max_connections_per_tenant
        return 1000
    
    @max_connections_per_tenant.setter  
    def max_connections_per_tenant(self, value: int):
        """Set max connections per tenant."""
        if self._initialized:
            self._enhanced_manager.max_connections_per_tenant = value
    
    # Helper methods for backward compatibility
    async def broadcast_to_connections(
        self,
        connections: List[WebSocketConnection],
        message: Dict[str, Any]
    ):
        """Broadcast message to specific connections."""
        await self._ensure_initialized()
        for connection in connections:
            await self.send_to_connection(connection.id, message)
    
    # Clean up old references
    async def cleanup(self):
        """Cleanup all connections (for shutdown)."""
        if self._initialized:
            await self._enhanced_manager.shutdown()


# Global connection manager instance
_connection_manager: Optional[ConnectionManager] = None


def get_connection_manager() -> ConnectionManager:
    """Get singleton connection manager instance."""
    global _connection_manager
    if _connection_manager is None:
        _connection_manager = ConnectionManager()
    return _connection_manager