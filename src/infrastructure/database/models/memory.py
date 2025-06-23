"""
User preferences model - the only memory-related model that belongs in PostgreSQL.
Actual memory/embeddings are stored in vector databases (Milvus/Chroma).
"""
from sqlalchemy import JSON, Column, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from ..base import BaseModel


class UserPreferences(BaseModel):
    """
    User preferences and settings.
    This belongs in PostgreSQL as it's structured configuration data, not embeddings.
    """
    __tablename__ = 'user_preferences'

    # Foreign Key
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False, unique=True)

    # Language & Localization
    language_preferences = Column(JSON, default=lambda: {
        "primary_language": "en",
        "fallback_language": "en",
        "date_format": "MM/DD/YYYY",
        "time_format": "12h",
        "timezone": "UTC"
    })

    # Interface Preferences
    interface_preferences = Column(JSON, default=lambda: {
        "theme": "system",  # light, dark, system
        "density": "comfortable",  # compact, comfortable, spacious
        "sidebar_collapsed": False,
        "show_avatars": True,
        "animation_speed": "normal"
    })

    # Notification Settings
    notification_preferences = Column(JSON, default=lambda: {
        "email_notifications": True,
        "push_notifications": True,
        "sound_enabled": True,
        "mention_notifications": True,
        "dm_notifications": True,
        "team_notifications": True
    })

    # AI/Assistant Preferences
    ai_preferences = Column(JSON, default=lambda: {
        "preferred_model": None,
        "preferred_provider": None,
        "temperature": 0.7,
        "max_tokens": 4096,
        "stream_responses": True,
        "auto_suggestions": True
    })

    # Privacy Settings
    privacy_settings = Column(JSON, default=lambda: {
        "profile_visibility": "team",  # public, team, private
        "activity_status": True,
        "typing_indicators": True,
        "read_receipts": True,
        "data_retention_days": 365
    })

    # Relationships
    user = relationship("User", back_populates="preferences")

    def __repr__(self):
        return f"<UserPreferences(user_id={self.user_id})>"
