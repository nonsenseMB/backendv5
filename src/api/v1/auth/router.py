"""Authentication API router."""
from fastapi import APIRouter

from .certificate_endpoints import router as certificate_router
from .device_endpoints import router as device_router
from .device_management import router as device_management_router
from .token import router as token_router

# Create the main auth router
router = APIRouter(prefix="/auth", tags=["authentication"])

# Include sub-routers
router.include_router(token_router)
router.include_router(device_router)
router.include_router(certificate_router)
router.include_router(device_management_router)
