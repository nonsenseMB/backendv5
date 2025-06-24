"""
WebSocket API module for real-time communication.
Provides secure WebSocket connections with JWT authentication.
"""

from .auth import WebSocketAuthenticator
from .connection_manager import ConnectionManager, WebSocketConnection
from .handlers import websocket_endpoint
from .router import router

__all__ = [
    "WebSocketAuthenticator",
    "ConnectionManager", 
    "WebSocketConnection",
    "websocket_endpoint",
    "router"
]