"""
User preferences endpoints.
Handles user preferences and settings management.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ....core.logging import get_logger
from ....infrastructure.database.models.memory import UserPreferences
from ....infrastructure.database.session import get_db
from ...dependencies.context import get_current_user
from .schemas import (
    AIPreferences,
    LanguagePreferences,
    NotificationPreferences,
    UserPreferencesResponse,
    UserPreferencesUpdate,
)

router = APIRouter(prefix="/me/preferences", tags=["user-preferences"])
logger = get_logger(__name__)


@router.get("", response_model=UserPreferencesResponse)
async def get_my_preferences(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get current user's preferences."""
    preferences = db.query(UserPreferences).filter(
        UserPreferences.user_id == current_user["id"]
    ).first()

    if not preferences:
        # Create default preferences if none exist
        preferences = UserPreferences(user_id=current_user["id"])
        db.add(preferences)
        db.commit()
        db.refresh(preferences)

    return UserPreferencesResponse(
        language_preferences=preferences.language_preferences,
        interface_preferences=preferences.interface_preferences,
        notification_preferences=preferences.notification_preferences,
        ai_preferences=preferences.ai_preferences,
        privacy_settings=preferences.privacy_settings
    )


@router.put("", response_model=UserPreferencesResponse)
async def update_my_preferences(
    preferences_update: UserPreferencesUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update current user's preferences."""
    preferences = db.query(UserPreferences).filter(
        UserPreferences.user_id == current_user["id"]
    ).first()

    if not preferences:
        # Create new preferences if none exist
        preferences = UserPreferences(user_id=current_user["id"])
        db.add(preferences)
        db.flush()  # Get the ID

    # Update preferences fields that were provided
    update_data = preferences_update.dict(exclude_unset=True)

    for field, value in update_data.items():
        if hasattr(preferences, field):
            # Merge with existing preferences to preserve fields not being updated
            current_prefs = getattr(preferences, field) or {}
            if isinstance(value, dict):
                # For dict fields, merge with existing values
                merged_prefs = {**current_prefs, **value.dict()}
                setattr(preferences, field, merged_prefs)
            else:
                setattr(preferences, field, value.dict() if hasattr(value, 'dict') else value)

    try:
        db.commit()
        db.refresh(preferences)

        logger.info(
            "User preferences updated",
            user_id=str(current_user["id"]),
            updated_fields=list(update_data.keys())
        )

        return UserPreferencesResponse(
            language_preferences=preferences.language_preferences,
            interface_preferences=preferences.interface_preferences,
            notification_preferences=preferences.notification_preferences,
            ai_preferences=preferences.ai_preferences,
            privacy_settings=preferences.privacy_settings
        )

    except Exception as e:
        db.rollback()
        logger.error(
            "Failed to update user preferences",
            user_id=str(current_user["id"]),
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update preferences"
        )


@router.get("/language", response_model=LanguagePreferences)
async def get_language_preferences(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get current user's language preferences."""
    preferences = db.query(UserPreferences).filter(
        UserPreferences.user_id == current_user["id"]
    ).first()

    if not preferences:
        return LanguagePreferences()

    return LanguagePreferences(**preferences.language_preferences)


@router.put("/language", response_model=LanguagePreferences)
async def update_language_preferences(
    language_prefs: LanguagePreferences,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update current user's language preferences."""
    preferences = db.query(UserPreferences).filter(
        UserPreferences.user_id == current_user["id"]
    ).first()

    if not preferences:
        preferences = UserPreferences(
            user_id=current_user["id"],
            language_preferences=language_prefs.dict()
        )
        db.add(preferences)
    else:
        preferences.language_preferences = language_prefs.dict()

    try:
        db.commit()
        db.refresh(preferences)

        logger.info(
            "Language preferences updated",
            user_id=str(current_user["id"])
        )

        return LanguagePreferences(**preferences.language_preferences)

    except Exception as e:
        db.rollback()
        logger.error(
            "Failed to update language preferences",
            user_id=str(current_user["id"]),
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update language preferences"
        )


@router.get("/ai", response_model=AIPreferences)
async def get_ai_preferences(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get current user's AI preferences."""
    preferences = db.query(UserPreferences).filter(
        UserPreferences.user_id == current_user["id"]
    ).first()

    if not preferences:
        return AIPreferences()

    return AIPreferences(**preferences.ai_preferences)


@router.put("/ai", response_model=AIPreferences)
async def update_ai_preferences(
    ai_prefs: AIPreferences,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update current user's AI preferences."""
    preferences = db.query(UserPreferences).filter(
        UserPreferences.user_id == current_user["id"]
    ).first()

    if not preferences:
        preferences = UserPreferences(
            user_id=current_user["id"],
            ai_preferences=ai_prefs.dict()
        )
        db.add(preferences)
    else:
        preferences.ai_preferences = ai_prefs.dict()

    try:
        db.commit()
        db.refresh(preferences)

        logger.info(
            "AI preferences updated",
            user_id=str(current_user["id"])
        )

        return AIPreferences(**preferences.ai_preferences)

    except Exception as e:
        db.rollback()
        logger.error(
            "Failed to update AI preferences",
            user_id=str(current_user["id"]),
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update AI preferences"
        )


@router.get("/notifications", response_model=NotificationPreferences)
async def get_notification_preferences(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get current user's notification preferences."""
    preferences = db.query(UserPreferences).filter(
        UserPreferences.user_id == current_user["id"]
    ).first()

    if not preferences:
        return NotificationPreferences()

    return NotificationPreferences(**preferences.notification_preferences)


@router.put("/notifications", response_model=NotificationPreferences)
async def update_notification_preferences(
    notification_prefs: NotificationPreferences,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update current user's notification preferences."""
    preferences = db.query(UserPreferences).filter(
        UserPreferences.user_id == current_user["id"]
    ).first()

    if not preferences:
        preferences = UserPreferences(
            user_id=current_user["id"],
            notification_preferences=notification_prefs.dict()
        )
        db.add(preferences)
    else:
        preferences.notification_preferences = notification_prefs.dict()

    try:
        db.commit()
        db.refresh(preferences)

        logger.info(
            "Notification preferences updated",
            user_id=str(current_user["id"])
        )

        return NotificationPreferences(**preferences.notification_preferences)

    except Exception as e:
        db.rollback()
        logger.error(
            "Failed to update notification preferences",
            user_id=str(current_user["id"]),
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update notification preferences"
        )
