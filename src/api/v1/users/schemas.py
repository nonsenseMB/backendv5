"""
User profile and preferences schemas.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


class UserBasicResponse(BaseModel):
    """Basic user info for references in other responses."""
    id: UUID
    email: EmailStr
    username: str | None = None
    full_name: str | None = None
    avatar_url: str | None = None
    
    class Config:
        from_attributes = True


class NotificationPreferences(BaseModel):
    """Notification preferences schema."""
    email_notifications: bool = Field(default=True, description="Enable email notifications")
    push_notifications: bool = Field(default=True, description="Enable push notifications")
    sound_enabled: bool = Field(default=True, description="Enable notification sounds")
    mention_notifications: bool = Field(default=True, description="Notify on mentions")
    dm_notifications: bool = Field(default=True, description="Notify on direct messages")
    team_notifications: bool = Field(default=True, description="Notify on team activity")


class AIPreferences(BaseModel):
    """AI assistant preferences schema."""
    preferred_model: str | None = Field(None, description="Preferred AI model")
    preferred_provider: str | None = Field(None, description="Preferred AI provider")
    temperature: float = Field(default=0.7, ge=0.0, le=2.0, description="AI temperature setting")
    max_tokens: int = Field(default=4096, ge=1, le=32000, description="Maximum response tokens")
    stream_responses: bool = Field(default=True, description="Enable streaming responses")
    auto_suggestions: bool = Field(default=True, description="Enable auto-suggestions")


class PrivacySettings(BaseModel):
    """Privacy settings schema."""
    profile_visibility: str = Field(default="team", description="Profile visibility level", pattern="^(public|team|private)$")
    activity_status: bool = Field(default=True, description="Show activity status")
    typing_indicators: bool = Field(default=True, description="Show typing indicators")
    read_receipts: bool = Field(default=True, description="Show read receipts")
    data_retention_days: int = Field(default=365, ge=30, le=2555, description="Data retention period in days")


class InterfacePreferences(BaseModel):
    """Interface preferences schema."""
    theme: str = Field(default="system", description="UI theme", pattern="^(light|dark|system)$")
    density: str = Field(default="comfortable", description="UI density", pattern="^(compact|comfortable|spacious)$")
    sidebar_collapsed: bool = Field(default=False, description="Sidebar collapsed state")
    show_avatars: bool = Field(default=True, description="Show user avatars")
    animation_speed: str = Field(default="normal", description="Animation speed", pattern="^(slow|normal|fast)$")


class LanguagePreferences(BaseModel):
    """Language and localization preferences schema."""
    primary_language: str = Field(default="en", description="Primary language code")
    fallback_language: str = Field(default="en", description="Fallback language code")
    date_format: str = Field(default="MM/DD/YYYY", description="Date format preference")
    time_format: str = Field(default="12h", description="Time format preference", pattern="^(12h|24h)$")
    timezone: str = Field(default="UTC", description="User timezone")


class UserPreferencesResponse(BaseModel):
    """Complete user preferences response schema."""
    language_preferences: LanguagePreferences
    interface_preferences: InterfacePreferences
    notification_preferences: NotificationPreferences
    ai_preferences: AIPreferences
    privacy_settings: PrivacySettings

    class Config:
        from_attributes = True


class UserPreferencesUpdate(BaseModel):
    """User preferences update schema."""
    language_preferences: LanguagePreferences | None = None
    interface_preferences: InterfacePreferences | None = None
    notification_preferences: NotificationPreferences | None = None
    ai_preferences: AIPreferences | None = None
    privacy_settings: PrivacySettings | None = None


class UserProfileResponse(BaseModel):
    """User profile response schema."""
    id: UUID
    email: EmailStr
    username: str | None = None
    full_name: str | None = None
    avatar_url: str | None = None
    language: str
    timezone: str
    external_id: str
    is_active: bool
    is_verified: bool
    last_seen_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    preferences: UserPreferencesResponse | None = None

    class Config:
        from_attributes = True


class UserProfileUpdate(BaseModel):
    """User profile update schema."""
    full_name: str | None = Field(None, max_length=255, description="Full display name")
    avatar_url: str | None = Field(None, description="Profile picture URL")
    language: str | None = Field(None, max_length=10, description="Language preference")
    timezone: str | None = Field(None, max_length=50, description="Timezone preference")


class UserTenantInfo(BaseModel):
    """User's tenant membership info."""
    tenant_id: UUID
    tenant_name: str
    tenant_slug: str
    user_role: str
    is_active: bool
    joined_at: datetime
    last_accessed: datetime | None = None
    permissions: list[str] = Field(default=[], description="User permissions in this tenant")

    class Config:
        from_attributes = True


class AccountDeletionRequest(BaseModel):
    """Account deletion request schema."""
    confirmation: str = Field(..., description="Must be 'DELETE' to confirm")
    reason: str | None = Field(None, max_length=500, description="Optional reason for deletion")

    def __init__(self, **data):
        super().__init__(**data)
        if self.confirmation != "DELETE":
            raise ValueError("Confirmation must be 'DELETE' to proceed with account deletion")


class AccountDeletionResponse(BaseModel):
    """Account deletion response schema."""
    request_id: UUID = Field(..., description="Deletion request tracking ID")
    status: str = Field(..., description="Deletion request status")
    scheduled_deletion_date: datetime = Field(..., description="When the account will be deleted")
    data_export_url: str | None = Field(None, description="URL to download user data")
    message: str = Field(..., description="Confirmation message")


class UserSession(BaseModel):
    """User session information schema."""
    session_id: UUID
    device_info: str | None = None
    ip_address_hash: str | None = None
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    is_current: bool = Field(default=False, description="Is this the current session")

    class Config:
        from_attributes = True
