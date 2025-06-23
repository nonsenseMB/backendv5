"""
User preferences repository - the only memory-related repository for PostgreSQL.
Actual memory operations (embeddings, RAG) should use vector database services.
"""
from uuid import UUID

from infrastructure.database.models.memory import UserPreferences
from infrastructure.database.repositories.base import BaseRepository


class UserPreferencesRepository(BaseRepository[UserPreferences]):
    """Repository for UserPreferences model."""

    async def get_user_preferences(self, user_id: UUID) -> UserPreferences | None:
        """Get preferences for a user."""
        return await self.get_by(user_id=user_id)

    async def create_or_update_preferences(
        self,
        user_id: UUID,
        language_preferences: dict = None,
        interface_preferences: dict = None,
        notification_preferences: dict = None,
        ai_preferences: dict = None,
        privacy_settings: dict = None
    ) -> UserPreferences:
        """Create or update user preferences."""
        existing = await self.get_user_preferences(user_id)

        update_data = {}
        if language_preferences is not None:
            update_data['language_preferences'] = language_preferences
        if interface_preferences is not None:
            update_data['interface_preferences'] = interface_preferences
        if notification_preferences is not None:
            update_data['notification_preferences'] = notification_preferences
        if ai_preferences is not None:
            update_data['ai_preferences'] = ai_preferences
        if privacy_settings is not None:
            update_data['privacy_settings'] = privacy_settings

        if existing:
            # Merge with existing preferences
            for key, value in update_data.items():
                if isinstance(value, dict) and isinstance(getattr(existing, key), dict):
                    # Merge dictionaries
                    current = getattr(existing, key)
                    current.update(value)
                    update_data[key] = current

            return await self.update(existing.id, **update_data)
        else:
            # Create new preferences
            return await self.create(
                user_id=user_id,
                language_preferences=language_preferences or {},
                interface_preferences=interface_preferences or {},
                notification_preferences=notification_preferences or {},
                ai_preferences=ai_preferences or {},
                privacy_settings=privacy_settings or {}
            )

    async def update_ai_model_preference(
        self,
        user_id: UUID,
        model: str,
        provider: str = None
    ) -> UserPreferences | None:
        """Update preferred AI model."""
        prefs = await self.get_user_preferences(user_id)
        if not prefs:
            return await self.create_or_update_preferences(
                user_id=user_id,
                ai_preferences={'preferred_model': model, 'preferred_provider': provider}
            )

        ai_prefs = prefs.ai_preferences or {}
        ai_prefs['preferred_model'] = model
        if provider:
            ai_prefs['preferred_provider'] = provider

        return await self.update(prefs.id, ai_preferences=ai_prefs)

    async def update_theme_preference(
        self,
        user_id: UUID,
        theme: str
    ) -> UserPreferences | None:
        """Update theme preference."""
        prefs = await self.get_user_preferences(user_id)
        if not prefs:
            return await self.create_or_update_preferences(
                user_id=user_id,
                interface_preferences={'theme': theme}
            )

        interface_prefs = prefs.interface_preferences or {}
        interface_prefs['theme'] = theme

        return await self.update(prefs.id, interface_preferences=interface_prefs)
