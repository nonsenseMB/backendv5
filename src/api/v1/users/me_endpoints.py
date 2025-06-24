"""
User profile endpoints for /me routes.
Handles current user profile management.
"""


from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ....core.logging import get_logger
from ....infrastructure.database.models.auth import User
from ....infrastructure.database.models.memory import UserPreferences
from ....infrastructure.database.models.tenant import TenantUser
from ....infrastructure.database.session import get_db
from ...dependencies.context import get_current_user
from .schemas import (
    AccountDeletionRequest,
    AccountDeletionResponse,
    UserPreferencesResponse,
    UserProfileResponse,
    UserProfileUpdate,
    UserTenantInfo,
)

router = APIRouter(prefix="/me", tags=["user-profile"])
logger = get_logger(__name__)


@router.get("", response_model=UserProfileResponse)
async def get_my_profile(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get current user's profile with preferences."""
    user = db.query(User).filter(User.id == current_user["id"]).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Get user preferences
    preferences = db.query(UserPreferences).filter(
        UserPreferences.user_id == user.id
    ).first()

    # Convert preferences to response format
    preferences_response = None
    if preferences:
        preferences_response = UserPreferencesResponse(
            language_preferences=preferences.language_preferences,
            interface_preferences=preferences.interface_preferences,
            notification_preferences=preferences.notification_preferences,
            ai_preferences=preferences.ai_preferences,
            privacy_settings=preferences.privacy_settings
        )

    return UserProfileResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        avatar_url=user.avatar_url,
        language=user.language,
        timezone=user.timezone,
        external_id=user.external_id,
        is_active=user.is_active,
        is_verified=user.is_verified,
        last_seen_at=user.last_seen_at,
        created_at=user.created_at,
        updated_at=user.updated_at,
        preferences=preferences_response
    )


@router.put("", response_model=UserProfileResponse)
async def update_my_profile(
    profile_update: UserProfileUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update current user's profile."""
    user = db.query(User).filter(User.id == current_user["id"]).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Update fields that were provided
    update_data = profile_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(user, field, value)

    try:
        db.commit()
        db.refresh(user)

        logger.info(
            "User profile updated",
            user_id=str(user.id),
            updated_fields=list(update_data.keys())
        )

        # Get updated preferences for response
        preferences = db.query(UserPreferences).filter(
            UserPreferences.user_id == user.id
        ).first()

        preferences_response = None
        if preferences:
            preferences_response = UserPreferencesResponse(
                language_preferences=preferences.language_preferences,
                interface_preferences=preferences.interface_preferences,
                notification_preferences=preferences.notification_preferences,
                ai_preferences=preferences.ai_preferences,
                privacy_settings=preferences.privacy_settings
            )

        return UserProfileResponse(
            id=user.id,
            email=user.email,
            username=user.username,
            full_name=user.full_name,
            avatar_url=user.avatar_url,
            language=user.language,
            timezone=user.timezone,
            external_id=user.external_id,
            is_active=user.is_active,
            is_verified=user.is_verified,
            last_seen_at=user.last_seen_at,
            created_at=user.created_at,
            updated_at=user.updated_at,
            preferences=preferences_response
        )

    except Exception as e:
        db.rollback()
        logger.error(
            "Failed to update user profile",
            user_id=str(user.id),
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update profile"
        )


@router.get("/tenants", response_model=list[UserTenantInfo])
async def get_my_tenants(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get list of tenants the current user belongs to."""
    from ....core.auth.permissions import PermissionChecker
    from ....infrastructure.database.models.tenant import Tenant

    # Get user's tenant memberships
    tenant_users = (
        db.query(TenantUser, Tenant)
        .join(Tenant, TenantUser.tenant_id == Tenant.id)
        .filter(
            TenantUser.user_id == current_user["id"],
            TenantUser.is_active == True,
            Tenant.is_active == True
        )
        .all()
    )

    result = []
    permission_checker = PermissionChecker(db)

    for tenant_user, tenant in tenant_users:
        # Get user permissions in this tenant
        permissions = await permission_checker.get_user_permissions(
            current_user["id"], tenant.id
        )

        result.append(UserTenantInfo(
            tenant_id=tenant.id,
            tenant_name=tenant.name,
            tenant_slug=tenant.slug,
            user_role=tenant_user.role,
            is_active=tenant_user.is_active,
            joined_at=tenant_user.joined_at,
            last_accessed=datetime.utcnow(),
            permissions=list(permissions)
        ))

    return result


@router.delete("", response_model=AccountDeletionResponse)
async def request_account_deletion(
    deletion_request: AccountDeletionRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Request account deletion (GDPR compliance).
    This schedules the account for deletion after a grace period.
    """
    import uuid
    from datetime import datetime, timedelta

    user = db.query(User).filter(User.id == current_user["id"]).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Create deletion request tracking
    deletion_id = uuid.uuid4()
    scheduled_date = datetime.utcnow() + timedelta(days=30)  # 30-day grace period

    # In a real implementation, you would:
    # 1. Create a deletion request record
    # 2. Schedule background job for actual deletion
    # 3. Generate data export
    # 4. Send confirmation email

    logger.warning(
        "Account deletion requested",
        user_id=str(user.id),
        email=user.email,
        reason=deletion_request.reason,
        deletion_id=str(deletion_id)
    )

    # For now, just mark user as inactive
    user.is_active = False
    db.commit()

    return AccountDeletionResponse(
        request_id=deletion_id,
        status="scheduled",
        scheduled_deletion_date=scheduled_date,
        data_export_url=None,  # Would be implemented with actual data export
        message="Account deletion has been scheduled. You have 30 days to cancel this request."
    )
