"""Request context management for logging and auditing."""
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from src.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class RequestContext:
    """
    Context information for the current request.
    
    This dataclass holds all request-scoped information that needs to be
    available throughout the request lifecycle, especially for logging,
    auditing, and authorization purposes.
    """
    # Core identifiers
    request_id: str
    user_id: str
    tenant_id: str
    session_id: str

    # Authorization data
    permissions: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)

    # Request metadata
    ip_address: str | None = None
    user_agent: str | None = None
    device_id: str | None = None
    api_version: str | None = None

    # Request details
    method: str | None = None
    path: str | None = None
    query_params: dict[str, Any] = field(default_factory=dict)

    # Timing information
    start_time: datetime = field(default_factory=lambda: datetime.now(UTC))

    # Additional context
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert context to dictionary for logging."""
        return {
            "request_id": self.request_id,
            "user_id": self.user_id,
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "permissions": self.permissions,
            "groups": self.groups,
            "roles": self.roles,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "device_id": self.device_id,
            "api_version": self.api_version,
            "method": self.method,
            "path": self.path,
            "start_time": self.start_time.isoformat(),
            **self.extra
        }


# Thread-safe context variable
_request_context: ContextVar[RequestContext | None] = ContextVar(
    "request_context", default=None
)


def get_request_context() -> RequestContext | None:
    """
    Get the current request context.
    
    Returns:
        The current RequestContext or None if not set
    """
    return _request_context.get()


def set_request_context(context: RequestContext) -> None:
    """
    Set the request context.
    
    Args:
        context: The RequestContext to set
    """
    _request_context.set(context)
    logger.debug(
        "Request context set",
        request_id=context.request_id,
        user_id=context.user_id,
        tenant_id=context.tenant_id
    )


def clear_request_context() -> None:
    """Clear the request context."""
    context = get_request_context()
    if context:
        logger.debug(
            "Request context cleared",
            request_id=context.request_id
        )
    _request_context.set(None)


def create_request_id() -> str:
    """Generate a unique request ID."""
    return str(uuid.uuid4())


def require_request_context() -> RequestContext:
    """
    Get the current request context, raising an error if not set.
    
    Returns:
        The current RequestContext
        
    Raises:
        RuntimeError: If no request context is set
    """
    context = get_request_context()
    if not context:
        raise RuntimeError("No request context set. This operation requires an active request.")
    return context


class RequestContextManager:
    """
    Context manager for temporarily setting request context.
    
    This is useful for background tasks or when you need to temporarily
    switch request context.
    """

    def __init__(self, context: RequestContext):
        self.context = context
        self.previous_context: RequestContext | None = None

    def __enter__(self):
        """Store previous context and set new one."""
        self.previous_context = get_request_context()
        set_request_context(self.context)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Restore previous context."""
        if self.previous_context:
            set_request_context(self.previous_context)
        else:
            clear_request_context()


def update_request_context(**kwargs) -> None:
    """
    Update fields in the current request context.
    
    Args:
        **kwargs: Fields to update in the context
        
    Raises:
        RuntimeError: If no request context is set
    """
    context = require_request_context()

    for key, value in kwargs.items():
        if hasattr(context, key):
            setattr(context, key, value)
        else:
            # Store unknown fields in extra
            context.extra[key] = value

    logger.debug(
        "Request context updated",
        request_id=context.request_id,
        updates=list(kwargs.keys())
    )
