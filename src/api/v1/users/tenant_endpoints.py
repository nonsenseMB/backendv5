"""
Tenant switching and management endpoints.
Handles tenant switching functionality for users.
"""

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ....core.auth.tenant_switcher import TenantSwitcher
from ....core.logging import get_logger
from ....infrastructure.database.session import get_db
from ...dependencies.context import get_current_user, get_tenant_context
from .schemas import UserTenantInfo

router = APIRouter(prefix="/me/tenant", tags=["tenant-switching"])
logger = get_logger(__name__)


class TenantSwitchRequest(BaseModel):
    """Tenant switch request schema."""
    tenant_id: UUID


class TenantSwitchResponse(BaseModel):
    """Tenant switch response schema."""
    access_token: str
    refresh_token: str
    tenant: UserTenantInfo


@router.get("/current", response_model=UserTenantInfo)
async def get_current_tenant_info(
    current_user: dict = Depends(get_current_user),
    tenant_id: UUID = Depends(get_tenant_context),
    db: Session = Depends(get_db)
):
    """Get current tenant information for the user."""
    tenant_switcher = TenantSwitcher(db)

    membership = await tenant_switcher.get_current_tenant_info(
        user_id=current_user["id"],
        tenant_id=tenant_id
    )

    if not membership:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found or user not a member"
        )

    return UserTenantInfo(
        tenant_id=membership.tenant_id,
        tenant_name=membership.tenant_name,
        tenant_slug=membership.tenant_slug,
        user_role=membership.user_role,
        is_active=membership.is_active,
        joined_at=membership.joined_at,
        last_accessed=datetime.utcnow(),
        permissions=membership.permissions
    )


@router.post("/switch", response_model=TenantSwitchResponse)
async def switch_tenant(
    switch_request: TenantSwitchRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Switch to a different tenant.
    Issues new tokens with the target tenant context.
    """
    tenant_switcher = TenantSwitcher(db)

    try:
        # Use TenantSwitcher service for secure tenant switching
        switch_result = await tenant_switcher.switch_tenant(
            user_id=current_user["id"],
            target_tenant_id=switch_request.tenant_id,
            current_session_id=current_user.get("session_id")
        )

        # Convert tenant info to schema format
        tenant_info = UserTenantInfo(
            tenant_id=switch_result["tenant"]["tenant_id"],
            tenant_name=switch_result["tenant"]["tenant_name"],
            tenant_slug=switch_result["tenant"]["tenant_slug"],
            user_role=switch_result["tenant"]["user_role"],
            is_active=switch_result["tenant"]["is_active"],
            joined_at=switch_result["tenant"]["joined_at"],
            last_accessed=switch_result["tenant"]["last_accessed"],
            permissions=switch_result["tenant"]["permissions"]
        )

        return TenantSwitchResponse(
            access_token=switch_result["access_token"],
            refresh_token=switch_result["refresh_token"],
            tenant=tenant_info
        )

    except Exception as e:
        logger.error(
            "Failed to switch tenant",
            user_id=str(current_user["id"]),
            target_tenant_id=str(switch_request.tenant_id),
            error=str(e)
        )
        raise


@router.get("/available", response_model=list[UserTenantInfo])
async def get_available_tenants(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get list of tenants the user can switch to.
    This is the same as the tenants list in me_endpoints but specific to switching context.
    """
    tenant_switcher = TenantSwitcher(db)

    # Get user's tenant memberships using TenantSwitcher service
    memberships = await tenant_switcher.get_user_tenants(current_user["id"])

    result = []
    for membership in memberships:
        result.append(UserTenantInfo(
            tenant_id=membership.tenant_id,
            tenant_name=membership.tenant_name,
            tenant_slug=membership.tenant_slug,
            user_role=membership.user_role,
            is_active=membership.is_active,
            joined_at=membership.joined_at,
            last_accessed=membership.last_accessed,
            permissions=membership.permissions
        ))

    return result
