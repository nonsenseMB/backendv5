"""
Main user management router.
Combines all user-related endpoints.
"""

from fastapi import APIRouter

from .me_endpoints import router as me_router
from .preferences_endpoints import router as preferences_router
from .session_endpoints import router as session_router
from .tenant_endpoints import router as tenant_router

# Create the main users router
router = APIRouter(prefix="/users", tags=["users"])

# Include sub-routers
router.include_router(me_router)
router.include_router(preferences_router)
router.include_router(tenant_router)
router.include_router(session_router)
