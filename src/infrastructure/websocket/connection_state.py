"""
WebSocket connection state models and management.
Provides data structures for tracking connection metadata and state.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Set, Optional, Dict, Any
from enum import Enum
import time


class ConnectionStatus(str, Enum):
    """WebSocket connection status."""
    CONNECTING = "connecting"
    CONNECTED = "connected"
    AUTHENTICATED = "authenticated"
    DISCONNECTING = "disconnecting"
    DISCONNECTED = "disconnected"


class RateLimitAction(str, Enum):
    """Rate limit action types."""
    MESSAGE_CREATE = "message.create"
    MESSAGE_EDIT = "message.edit"
    MESSAGE_DELETE = "message.delete"
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"
    PRESENCE_UPDATE = "presence.update"
    FILE_UPLOAD = "file.upload"
    DEFAULT = "default"


@dataclass
class RateLimitBucket:
    """Token bucket for rate limiting."""
    tokens: float
    last_refill: float
    max_tokens: int
    refill_rate: float  # tokens per second
    
    def consume(self, tokens: int = 1) -> bool:
        """
        Attempt to consume tokens from bucket.
        Returns True if successful, False if rate limited.
        """
        now = time.time()
        elapsed = now - self.last_refill
        
        # Refill tokens
        refill_amount = elapsed * self.refill_rate
        self.tokens = min(self.max_tokens, self.tokens + refill_amount)
        self.last_refill = now
        
        # Try to consume
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False


@dataclass
class RateLimitState:
    """Rate limiting state for a connection."""
    buckets: Dict[RateLimitAction, RateLimitBucket] = field(default_factory=dict)
    
    def __post_init__(self):
        """Initialize default buckets."""
        default_limits = {
            RateLimitAction.MESSAGE_CREATE: (10, 60),  # 10 per minute
            RateLimitAction.MESSAGE_EDIT: (5, 60),     # 5 per minute
            RateLimitAction.MESSAGE_DELETE: (5, 60),   # 5 per minute
            RateLimitAction.SUBSCRIBE: (50, 60),       # 50 per minute
            RateLimitAction.UNSUBSCRIBE: (50, 60),     # 50 per minute
            RateLimitAction.PRESENCE_UPDATE: (20, 60), # 20 per minute
            RateLimitAction.FILE_UPLOAD: (5, 300),     # 5 per 5 minutes
            RateLimitAction.DEFAULT: (100, 60)         # 100 per minute
        }
        
        for action, (max_tokens, window_seconds) in default_limits.items():
            refill_rate = max_tokens / window_seconds
            self.buckets[action] = RateLimitBucket(
                tokens=max_tokens,
                last_refill=time.time(),
                max_tokens=max_tokens,
                refill_rate=refill_rate
            )
    
    def check_rate_limit(self, action: RateLimitAction, tokens: int = 1) -> bool:
        """Check if action is rate limited."""
        bucket = self.buckets.get(action, self.buckets[RateLimitAction.DEFAULT])
        return bucket.consume(tokens)


@dataclass
class ConnectionMetadata:
    """
    Metadata for a WebSocket connection.
    Tracks subscriptions, permissions, and rate limits.
    """
    user_id: str
    tenant_id: str
    session_id: str
    channels: Set[str] = field(default_factory=set)
    subscriptions: Set[str] = field(default_factory=set)
    permissions: Optional[Set[str]] = None
    rate_limit: RateLimitState = field(default_factory=RateLimitState)
    custom_data: Dict[str, Any] = field(default_factory=dict)
    
    def add_channel(self, channel: str):
        """Add a channel subscription."""
        self.channels.add(channel)
    
    def remove_channel(self, channel: str):
        """Remove a channel subscription."""
        self.channels.discard(channel)
    
    def add_subscription(self, resource: str):
        """Add a resource subscription."""
        self.subscriptions.add(resource)
    
    def remove_subscription(self, resource: str):
        """Remove a resource subscription."""
        self.subscriptions.discard(resource)
    
    def update_permissions(self, permissions: Set[str]):
        """Update connection permissions."""
        self.permissions = permissions
    
    def has_permission(self, permission: str) -> bool:
        """Check if connection has permission."""
        return self.permissions is not None and permission in self.permissions
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "user_id": self.user_id,
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "channels": list(self.channels),
            "subscriptions": list(self.subscriptions),
            "permissions": list(self.permissions) if self.permissions else None,
            "custom_data": self.custom_data
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ConnectionMetadata":
        """Create from dictionary."""
        return cls(
            user_id=data["user_id"],
            tenant_id=data["tenant_id"],
            session_id=data["session_id"],
            channels=set(data.get("channels", [])),
            subscriptions=set(data.get("subscriptions", [])),
            permissions=set(data.get("permissions", [])) if data.get("permissions") else None,
            custom_data=data.get("custom_data", {})
        )


@dataclass
class ConnectionStats:
    """Statistics for a WebSocket connection."""
    messages_sent: int = 0
    messages_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    errors: int = 0
    last_error: Optional[str] = None
    last_error_time: Optional[datetime] = None
    
    def record_message_sent(self, size: int = 0):
        """Record a sent message."""
        self.messages_sent += 1
        self.bytes_sent += size
    
    def record_message_received(self, size: int = 0):
        """Record a received message."""
        self.messages_received += 1
        self.bytes_received += size
    
    def record_error(self, error: str):
        """Record an error."""
        self.errors += 1
        self.last_error = error
        self.last_error_time = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "messages_sent": self.messages_sent,
            "messages_received": self.messages_received,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "errors": self.errors,
            "last_error": self.last_error,
            "last_error_time": self.last_error_time.isoformat() if self.last_error_time else None
        }


@dataclass
class DistributedConnectionInfo:
    """
    Connection information for distributed tracking.
    Used for Redis-based state synchronization.
    """
    connection_id: str
    server_id: str
    user_id: str
    tenant_id: str
    session_id: str
    device_id: Optional[str]
    connected_at: datetime
    last_activity: datetime
    status: ConnectionStatus
    channels: Set[str]
    
    def to_redis_hash(self) -> Dict[str, str]:
        """Convert to Redis hash format."""
        return {
            "connection_id": self.connection_id,
            "server_id": self.server_id,
            "user_id": self.user_id,
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "device_id": self.device_id or "",
            "connected_at": self.connected_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "status": self.status.value,
            "channels": ",".join(self.channels)
        }
    
    @classmethod
    def from_redis_hash(cls, data: Dict[str, str]) -> "DistributedConnectionInfo":
        """Create from Redis hash data."""
        return cls(
            connection_id=data["connection_id"],
            server_id=data["server_id"],
            user_id=data["user_id"],
            tenant_id=data["tenant_id"],
            session_id=data["session_id"],
            device_id=data.get("device_id") or None,
            connected_at=datetime.fromisoformat(data["connected_at"]),
            last_activity=datetime.fromisoformat(data["last_activity"]),
            status=ConnectionStatus(data["status"]),
            channels=set(data["channels"].split(",")) if data["channels"] else set()
        )