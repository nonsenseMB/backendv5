"""API v1 router."""
from fastapi import APIRouter

from .auth.router import router as auth_router

# Create the main v1 router
router = APIRouter(prefix="/api/v1")

# Include module routers
router.include_router(auth_router)

# Future routers can be added here:
# router.include_router(users_router)
# router.include_router(documents_router)
# router.include_router(knowledge_router)
# etc.
