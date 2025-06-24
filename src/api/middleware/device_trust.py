"""Device trust middleware for request context injection."""
from typing import Optional
from uuid import UUID

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from src.core.auth.trust_manager import trust_manager
from src.core.logging import get_logger
from src.infrastructure.database.models.auth import UserDevice

logger = get_logger(__name__)


class DeviceTrustMiddleware(BaseHTTPMiddleware):
    """
    Middleware to inject device trust context into requests.
    
    This middleware:
    1. Extracts device ID from JWT claims
    2. Retrieves device trust score
    3. Records device activity for analytics
    4. Injects trust context into request state
    """
    
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint
    ) -> Response:
        """Process request with device trust context."""
        # Skip if no user context
        if not hasattr(request.state, "user"):
            return await call_next(request)
        
        # Skip if no device ID in token claims
        if not hasattr(request.state, "device_id"):
            return await call_next(request)
        
        device_id = request.state.device_id
        
        try:
            # Get device from database if needed
            # For now, we'll use trust score from JWT claims if available
            trust_score = getattr(request.state, "device_trust_score", None)
            
            if trust_score is None:
                # Get from database
                from src.infrastructure.database.session import get_async_session
                from src.infrastructure.database.repositories.device import DeviceRepository
                from src.infrastructure.database.unit_of_work import UnitOfWork
                
                session = await anext(get_async_session())
                try:
                    async with UnitOfWork(session) as uow:
                        device_repo = DeviceRepository(
                            UserDevice,
                            session,
                            request.state.user.tenant_id
                        )
                        device = await device_repo.get_by_id(UUID(device_id))
                        
                        if device:
                            trust_score = int(device.trust_score)
                            request.state.device_trust_score = trust_score
                finally:
                    await session.close()
            
            # Record device activity
            if trust_score is not None:
                trust_manager.record_device_event(
                    device_id=UUID(device_id),
                    event_type="api_access",
                    success=True,
                    metadata={
                        "endpoint": str(request.url.path),
                        "method": request.method,
                        "ip_address": request.client.host if request.client else None
                    }
                )
            
            # Get and inject policy
            if trust_score is not None:
                policy = trust_manager.get_device_policy(trust_score)
                request.state.device_policy = policy
                
                logger.debug(
                    "Device trust context injected",
                    device_id=device_id,
                    trust_score=trust_score,
                    trust_level=policy["trust_level"]
                )
        
        except Exception as e:
            # Don't fail the request on trust lookup errors
            logger.error(
                "Failed to inject device trust context",
                device_id=device_id,
                error=str(e),
                exc_info=True
            )
        
        # Continue with request
        response = await call_next(request)
        
        # Update device activity on response
        if hasattr(request.state, "device_trust_score"):
            try:
                # Record response status
                trust_manager.record_device_event(
                    device_id=UUID(device_id),
                    event_type="api_response",
                    success=(response.status_code < 400),
                    metadata={
                        "status_code": response.status_code,
                        "endpoint": str(request.url.path)
                    }
                )
            except Exception as e:
                logger.debug(
                    "Failed to record device response",
                    device_id=device_id,
                    error=str(e)
                )
        
        return response


def check_device_trust_required(
    request: Request,
    min_trust_score: int = 50
) -> bool:
    """
    Check if device meets minimum trust requirements.
    
    Args:
        request: FastAPI request
        min_trust_score: Minimum required trust score
        
    Returns:
        True if trust requirements are met
        
    Raises:
        HTTPException: If trust requirements not met
    """
    if not hasattr(request.state, "device_trust_score"):
        from fastapi import HTTPException, status
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Device trust verification required"
        )
    
    trust_score = request.state.device_trust_score
    if trust_score < min_trust_score:
        from fastapi import HTTPException, status
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Device trust score {trust_score} is below required {min_trust_score}"
        )
    
    return True