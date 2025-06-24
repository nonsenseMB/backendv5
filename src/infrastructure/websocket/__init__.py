"""
WebSocket infrastructure module.
Provides connection state management and distributed synchronization.
"""

from .connection_state import (
    ConnectionStatus,
    RateLimitAction,
    RateLimitBucket,
    RateLimitState,
    ConnectionMetadata,
    ConnectionStats,
    DistributedConnectionInfo
)

__all__ = [
    "ConnectionStatus",
    "RateLimitAction",
    "RateLimitBucket",
    "RateLimitState",
    "ConnectionMetadata",
    "ConnectionStats",
    "DistributedConnectionInfo"
]