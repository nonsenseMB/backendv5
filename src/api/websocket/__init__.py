"""
WebSocket API module for real-time communication.
Provides secure WebSocket connections with JWT authentication.
"""

from .auth import WebSocketAuthenticator
from .connection_manager import ConnectionManager, get_connection_manager
from .handlers import websocket_endpoint
from .router import router
from ...infrastructure.websocket.connection_manager import WebSocketConnection
from ...infrastructure.websocket.connection_state import ConnectionMetadata

__all__ = [
    "WebSocketAuthenticator",
    "ConnectionManager",
    "get_connection_manager",
    "WebSocketConnection",
    "ConnectionMetadata",
    "websocket_endpoint",
    "router"
]