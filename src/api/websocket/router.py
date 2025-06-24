"""
WebSocket router configuration.
Registers WebSocket endpoints with the FastAPI application.
"""

from fastapi import APIRouter

from .handlers import websocket_endpoint

# Create WebSocket router
router = APIRouter(
    prefix="/ws",
    tags=["websocket"]
)

# Register WebSocket endpoint
router.add_websocket_route("/", websocket_endpoint, name="websocket")