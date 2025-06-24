"""
Simple context dependencies for permission system.
"""

from typing import Optional
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ...infrastructure.database.session import get_db
from ...core.logging import get_logger

logger = get_logger(__name__)


def get_tenant_context(request: Request) -> UUID:
    """
    Simple tenant context extraction for permission middleware.
    
    Args:
        request: FastAPI request object
        
    Returns:
        UUID: Tenant ID
        
    Raises:
        HTTPException: If no tenant context found
    """
    # Get tenant ID from request state (set by tenant middleware)
    tenant_id = getattr(request.state, "tenant_id", None)
    
    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tenant context required"
        )
    
    if isinstance(tenant_id, str):
        try:
            return UUID(tenant_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid tenant ID"
            )
    
    return tenant_id


def get_current_user(request: Request) -> dict:
    """
    Simple user context extraction for permission middleware.
    
    Args:
        request: FastAPI request object
        
    Returns:
        dict: User context with ID and other fields
        
    Raises:
        HTTPException: If no user context found
    """
    # Get user from request state (set by auth middleware)
    user_id = getattr(request.state, "user_id", None)
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    
    # Return a minimal user context dict
    return {
        "id": user_id,
        "email": getattr(request.state, "user_email", None),
        "created_at": None,  # Placeholder
        "updated_at": None   # Placeholder
    }