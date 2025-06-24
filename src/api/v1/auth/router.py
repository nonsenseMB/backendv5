"""Authentication API router."""
from fastapi import APIRouter

from .token import router as token_router

# Create the main auth router
router = APIRouter(prefix="/auth", tags=["authentication"])

# Include sub-routers
router.include_router(token_router)

# Additional auth endpoints can be added here in the future
# For example: device registration, WebAuthn, etc.
