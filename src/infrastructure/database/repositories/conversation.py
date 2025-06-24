"""
Conversation repository implementation.
"""
from datetime import datetime
from uuid import UUID

from sqlalchemy import and_, or_, select

from src.infrastructure.database.models.conversation import Conversation, ConversationCheckpoint, Message
from src.infrastructure.database.repositories.base import BaseRepository, TenantAwareRepository


class ConversationRepository(TenantAwareRepository[Conversation]):
    """Repository for Conversation model."""

    async def get_user_conversations(
        self,
        user_id: UUID,
        skip: int = 0,
        limit: int = 20,
        include_archived: bool = False
    ) -> list[Conversation]:
        """Get conversations for a specific user in the current tenant."""
        filters = {'user_id': user_id}
        if not include_archived:
            filters['is_archived'] = False

        return await self.get_multi(
            skip=skip,
            limit=limit,
            filters=filters,
            order_by='-updated_at'
        )

    async def get_with_messages(
        self,
        conversation_id: UUID,
        message_limit: int = 50
    ) -> Conversation | None:
        """Get conversation with recent messages loaded."""
        # This would need a more complex query to limit messages
        return await self.get(conversation_id, load_relationships=['messages'])

    async def archive_conversation(self, conversation_id: UUID) -> Conversation | None:
        """Archive a conversation."""
        return await self.update(conversation_id, is_archived=True)

    async def unarchive_conversation(self, conversation_id: UUID) -> Conversation | None:
        """Unarchive a conversation."""
        return await self.update(conversation_id, is_archived=False)

    async def update_summary(
        self,
        conversation_id: UUID,
        summary: str,
        summary_model: str = None
    ) -> Conversation | None:
        """Update conversation summary."""
        update_data = {
            'summary': summary,
            'last_summary_at': datetime.utcnow()
        }
        if summary_model:
            update_data['summary_generated_by'] = summary_model

        return await self.update(conversation_id, **update_data)

    async def search_conversations(
        self,
        user_id: UUID,
        query: str,
        limit: int = 20
    ) -> list[Conversation]:
        """Search user conversations by title or summary."""
        search_term = f"%{query}%"
        stmt = select(Conversation).where(
            and_(
                Conversation.tenant_id == self.tenant_id,
                Conversation.user_id == user_id,
                or_(
                    Conversation.title.ilike(search_term),
                    Conversation.summary.ilike(search_term)
                )
            )
        ).limit(limit)

        result = await self.session.execute(stmt)
        return list(result.scalars().all())


class MessageRepository(BaseRepository[Message]):
    """Repository for Message model."""

    async def get_conversation_messages(
        self,
        conversation_id: UUID,
        skip: int = 0,
        limit: int = 50,
        order: str = 'asc'
    ) -> list[Message]:
        """Get messages for a conversation."""
        order_by = 'sequence_number' if order == 'asc' else '-sequence_number'

        return await self.get_multi(
            skip=skip,
            limit=limit,
            filters={'conversation_id': conversation_id},
            order_by=order_by
        )

    async def get_last_message(self, conversation_id: UUID) -> Message | None:
        """Get the last message in a conversation."""
        messages = await self.get_multi(
            limit=1,
            filters={'conversation_id': conversation_id},
            order_by='-sequence_number'
        )
        return messages[0] if messages else None

    async def create_message(
        self,
        conversation_id: UUID,
        role: str,
        content: str,
        model: str = None,
        tool_calls: dict = None,
        tool_results: dict = None,
        extra_data: dict = None
    ) -> Message:
        """Create a new message in a conversation."""
        # Get the next sequence number
        last_message = await self.get_last_message(conversation_id)
        sequence_number = (last_message.sequence_number + 1) if last_message else 1

        # Calculate token usage (simplified - you'd use a real tokenizer)
        token_count = len(content.split()) * 1.3  # Rough estimate

        return await self.create(
            conversation_id=conversation_id,
            sequence_number=sequence_number,
            role=role,
            content=content,
            model_used=model,
            total_tokens=int(token_count),
            tool_calls=tool_calls,
            tool_results=tool_results,
            extra_data=extra_data or {}
        )

    async def update_message_feedback(
        self,
        message_id: UUID,
        rating: int,
        feedback: str = None
    ) -> Message | None:
        """Update message feedback."""
        message = await self.get(message_id)
        if not message:
            return None

        extra_data = message.extra_data or {}
        extra_data['user_rating'] = rating
        if feedback:
            extra_data['user_feedback'] = feedback

        return await self.update(message_id, extra_data=extra_data)


class ConversationCheckpointRepository(BaseRepository[ConversationCheckpoint]):
    """Repository for ConversationCheckpoint model."""

    async def get_conversation_checkpoints(
        self,
        conversation_id: UUID,
        limit: int = 10
    ) -> list[ConversationCheckpoint]:
        """Get checkpoints for a conversation."""
        return await self.get_multi(
            limit=limit,
            filters={'conversation_id': conversation_id},
            order_by='-message_count'
        )

    async def create_checkpoint(
        self,
        conversation_id: UUID,
        message_count: int,
        summary: str,
        key_points: list[str] = None,
        context_data: dict = None
    ) -> ConversationCheckpoint:
        """Create a new checkpoint."""
        return await self.create(
            conversation_id=conversation_id,
            message_count=message_count,
            summary=summary,
            key_points=key_points or [],
            context_data=context_data or {}
        )

    async def get_latest_checkpoint(
        self,
        conversation_id: UUID
    ) -> ConversationCheckpoint | None:
        """Get the most recent checkpoint for a conversation."""
        checkpoints = await self.get_multi(
            limit=1,
            filters={'conversation_id': conversation_id},
            order_by='-created_at'
        )
        return checkpoints[0] if checkpoints else None
