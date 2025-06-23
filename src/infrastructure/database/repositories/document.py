"""
Document System repositories for CRUD operations and business logic.
"""

from uuid import UUID

from sqlalchemy import and_, desc, func, select
from sqlalchemy.orm import selectinload

from ..models.document import Document, DocumentContent, DocumentPermission, DocumentShare
from .base import BaseRepository, TenantAwareRepository


class DocumentRepository(TenantAwareRepository[Document]):
    """Repository for document management operations."""

    async def get_by_slug(self, slug: str, tenant_id: UUID) -> Document | None:
        """Get document by slug within tenant."""
        result = await self.session.execute(
            select(self.model)
            .where(and_(self.model.slug == slug, self.model.tenant_id == tenant_id))
            .options(
                selectinload(self.model.owner),
                selectinload(self.model.permissions),
                selectinload(self.model.content_versions)
            )
        )
        return result.scalar_one_or_none()

    async def get_user_documents(
        self,
        user_id: UUID,
        tenant_id: UUID,
        status: str | None = None,
        document_type: str | None = None,
        limit: int = 50,
        offset: int = 0
    ) -> list[Document]:
        """Get documents accessible by user."""
        query = select(self.model).where(
            and_(
                self.model.tenant_id == tenant_id,
                # User is owner OR has permissions
                (self.model.owner_id == user_id) |
                (self.model.permissions.any(DocumentPermission.user_id == user_id))
            )
        )

        if status:
            query = query.where(self.model.status == status)

        if document_type:
            query = query.where(self.model.document_type == document_type)

        return await self.session.execute(
            query.options(
                selectinload(self.model.owner),
                selectinload(self.model.last_editor)
            )
            .order_by(desc(self.model.last_edited_at))
            .limit(limit)
            .offset(offset)
        ).scalars().all()

    async def get_team_documents(
        self,
        team_id: UUID,
        tenant_id: UUID,
        limit: int = 50,
        offset: int = 0
    ) -> list[Document]:
        """Get documents belonging to a team."""
        return await self.session.execute(
            select(self.model)
            .where(and_(
                self.model.tenant_id == tenant_id,
                self.model.team_id == team_id
            ))
            .options(
                selectinload(self.model.owner),
                selectinload(self.model.last_editor)
            )
            .order_by(desc(self.model.last_edited_at))
            .limit(limit)
            .offset(offset)
        ).scalars().all()

    async def search_documents(
        self,
        query: str,
        tenant_id: UUID,
        user_id: UUID,
        limit: int = 20
    ) -> list[Document]:
        """Search documents by title and content."""
        # Note: In production, this should use full-text search
        return await self.session.execute(
            select(self.model)
            .where(and_(
                self.model.tenant_id == tenant_id,
                (self.model.owner_id == user_id) |
                (self.model.permissions.any(DocumentPermission.user_id == user_id)),
                self.model.title.ilike(f'%{query}%')
            ))
            .options(selectinload(self.model.owner))
            .order_by(desc(self.model.last_edited_at))
            .limit(limit)
        ).scalars().all()


class DocumentContentRepository(BaseRepository[DocumentContent]):
    """Repository for document content and version management."""

    async def get_current_content(self, document_id: UUID) -> DocumentContent | None:
        """Get current content version for document."""
        return await self.session.execute(
            select(self.model)
            .where(and_(
                self.model.document_id == document_id,
                self.model.is_current == True
            ))
            .options(selectinload(self.model.author))
        ).scalar_one_or_none()

    async def get_version_history(
        self,
        document_id: UUID,
        limit: int = 20
    ) -> list[DocumentContent]:
        """Get version history for document."""
        return await self.session.execute(
            select(self.model)
            .where(self.model.document_id == document_id)
            .options(selectinload(self.model.author))
            .order_by(desc(self.model.version))
            .limit(limit)
        ).scalars().all()

    async def create_new_version(
        self,
        document_id: UUID,
        author_id: UUID,
        content: dict,
        change_description: str | None = None
    ) -> DocumentContent:
        """Create new content version and mark as current."""
        # Get next version number
        result = await self.session.execute(
            select(func.max(self.model.version))
            .where(self.model.document_id == document_id)
        )
        latest_version = result.scalar() or 0

        # Mark all existing versions as not current
        await self.session.execute(
            select(self.model)
            .where(self.model.document_id == document_id)
            .update({"is_current": False})
        )

        # Create new version
        new_content = DocumentContent(
            document_id=document_id,
            version=latest_version + 1,
            is_current=True,
            content=content,
            author_id=author_id,
            change_description=change_description
        )

        return await self.create(new_content)


class DocumentPermissionRepository(BaseRepository[DocumentPermission]):
    """Repository for document permission management."""

    async def get_document_permissions(self, document_id: UUID) -> list[DocumentPermission]:
        """Get all permissions for a document."""
        return await self.session.execute(
            select(self.model)
            .where(self.model.document_id == document_id)
            .options(
                selectinload(self.model.user),
                selectinload(self.model.team),
                selectinload(self.model.grantor)
            )
        ).scalars().all()

    async def get_user_permission(
        self,
        document_id: UUID,
        user_id: UUID
    ) -> DocumentPermission | None:
        """Get user's permission for a document."""
        return await self.session.execute(
            select(self.model)
            .where(and_(
                self.model.document_id == document_id,
                self.model.user_id == user_id,
                self.model.is_active == True
            ))
        ).scalar_one_or_none()

    async def check_user_access(
        self,
        document_id: UUID,
        user_id: UUID,
        permission_type: str = 'read'
    ) -> bool:
        """Check if user has specific permission for document."""
        permission = await self.get_user_permission(document_id, user_id)

        if not permission:
            return False

        if permission_type == 'read':
            return permission.can_read
        elif permission_type == 'write':
            return permission.can_write
        elif permission_type == 'admin':
            return permission.can_admin
        elif permission_type == 'comment':
            return permission.can_comment
        elif permission_type == 'share':
            return permission.can_share

        return False

    async def grant_permission(
        self,
        document_id: UUID,
        user_id: UUID | None = None,
        team_id: UUID | None = None,
        permission_type: str = 'read',
        granted_by: UUID = None
    ) -> DocumentPermission:
        """Grant permission to user or team."""
        permission_data = {
            'document_id': document_id,
            'permission_type': permission_type,
            'granted_by': granted_by,
            'can_read': True,
            'can_write': permission_type in ['write', 'admin'],
            'can_admin': permission_type == 'admin',
            'can_comment': permission_type in ['comment', 'write', 'admin'],
            'can_share': permission_type in ['admin']
        }

        if user_id:
            permission_data['user_id'] = user_id
        elif team_id:
            permission_data['team_id'] = team_id
        else:
            raise ValueError("Either user_id or team_id must be provided")

        permission = DocumentPermission(**permission_data)
        return await self.create(permission)


class DocumentShareRepository(BaseRepository[DocumentShare]):
    """Repository for document sharing management."""

    async def get_by_token(self, share_token: str) -> DocumentShare | None:
        """Get share by token."""
        return await self.session.execute(
            select(self.model)
            .where(and_(
                self.model.share_token == share_token,
                self.model.is_active == True
            ))
            .options(
                selectinload(self.model.document),
                selectinload(self.model.creator)
            )
        ).scalar_one_or_none()

    async def get_document_shares(self, document_id: UUID) -> list[DocumentShare]:
        """Get all shares for a document."""
        return await self.session.execute(
            select(self.model)
            .where(self.model.document_id == document_id)
            .options(selectinload(self.model.creator))
            .order_by(desc(self.model.created_at))
        ).scalars().all()

    async def increment_view_count(self, share_id: UUID) -> bool:
        """Increment view count for share."""
        share = await self.get(share_id)
        if not share:
            return False

        if share.max_views and share.current_views >= share.max_views:
            return False

        share.current_views += 1
        await self.session.commit()
        return True
