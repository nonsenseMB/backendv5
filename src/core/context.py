"""Request context management for logging and auditing."""
import uuid
from contextvars import ContextVar
from dataclasses import dataclass


@dataclass
class RequestContext:
    """Context information for the current request."""
    tenant_id: str | None = None
    request_id: str | None = None
    user_id: str | None = None
    session_id: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None


# Thread-safe context variable
_request_context: ContextVar[RequestContext | None] = ContextVar(
    "request_context", default=None
)


def get_request_context() -> RequestContext | None:
    """Get the current request context."""
    return _request_context.get()


def set_request_context(context: RequestContext) -> None:
    """Set the request context."""
    _request_context.set(context)


def clear_request_context() -> None:
    """Clear the request context."""
    _request_context.set(None)


def create_request_id() -> str:
    """Generate a unique request ID."""
    return str(uuid.uuid4())
