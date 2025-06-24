"""
Agent system exceptions.
"""
from typing import Any, Optional
from uuid import UUID


class AgentError(Exception):
    """Base exception for agent-related errors."""
    
    def __init__(
        self,
        message: str,
        error_code: str = "agent_error",
        status_code: int = 400,
        details: Optional[dict[str, Any]] = None
    ):
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.details = details or {}
        super().__init__(message)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert exception to dictionary for API responses."""
        return {
            "error": self.error_code,
            "message": self.message,
            "details": self.details
        }


class AgentNotFoundError(AgentError):
    """Raised when an agent is not found."""
    
    def __init__(
        self,
        message: str = "Agent not found",
        agent_id: Optional[UUID] = None,
        details: Optional[dict[str, Any]] = None
    ):
        if agent_id:
            details = details or {}
            details["agent_id"] = str(agent_id)
        
        super().__init__(
            message=message,
            error_code="agent_not_found",
            status_code=404,
            details=details
        )


class AgentExecutionError(AgentError):
    """Raised when agent execution fails."""
    
    def __init__(
        self,
        message: str = "Agent execution failed",
        execution_id: Optional[str] = None,
        details: Optional[dict[str, Any]] = None
    ):
        if execution_id:
            details = details or {}
            details["execution_id"] = execution_id
        
        super().__init__(
            message=message,
            error_code="agent_execution_error",
            status_code=500,
            details=details
        )


class RateLimitExceededError(AgentError):
    """Raised when rate limits are exceeded."""
    
    def __init__(
        self,
        message: str = "Rate limit exceeded",
        limit_type: Optional[str] = None,
        retry_after: Optional[int] = None,
        details: Optional[dict[str, Any]] = None
    ):
        details = details or {}
        if limit_type:
            details["limit_type"] = limit_type
        if retry_after:
            details["retry_after"] = retry_after
        
        super().__init__(
            message=message,
            error_code="rate_limit_exceeded",
            status_code=429,
            details=details
        )


class ValidationError(AgentError):
    """Raised when validation fails."""
    
    def __init__(
        self,
        message: str = "Validation failed",
        field: Optional[str] = None,
        details: Optional[dict[str, Any]] = None
    ):
        if field:
            details = details or {}
            details["field"] = field
        
        super().__init__(
            message=message,
            error_code="validation_error",
            status_code=400,
            details=details
        )