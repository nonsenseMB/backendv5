"""
Document System models for collaborative writing and document management.
Supports TipTap editor, permissions, and real-time collaboration.
"""

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from ..base import BaseModel, TenantAwareModel


class Document(TenantAwareModel):
    """
    Main document model for collaborative writing.
    Supports TipTap editor and version control.
    """
    __tablename__ = 'documents'

    # Ownership
    owner_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    team_id = Column(UUID(as_uuid=True), ForeignKey('teams.id'), nullable=True)

    # Identity
    title = Column(String(500), nullable=False)
    slug = Column(String(500), nullable=True)
    description = Column(Text, nullable=True)

    # Document Type
    document_type = Column(String(50), nullable=False, default='document')  # document, note, template
    template_id = Column(UUID(as_uuid=True), ForeignKey('documents.id'), nullable=True)

    # Content
    content_type = Column(String(50), nullable=False, default='tiptap')  # tiptap, markdown, plain
    word_count = Column(Integer, default=0)
    character_count = Column(Integer, default=0)

    # Version Control
    version = Column(Integer, default=1)
    last_edited_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    last_edited_at = Column(DateTime, nullable=True)

    # Collaboration
    is_collaborative = Column(Boolean, default=True)
    max_collaborators = Column(Integer, default=10)
    current_collaborators = Column(Integer, default=0)

    # Status
    status = Column(String(50), default='draft')  # draft, published, archived, deleted
    is_public = Column(Boolean, default=False)
    is_template = Column(Boolean, default=False)

    # AI Features
    ai_assistance_enabled = Column(Boolean, default=True)
    ai_suggestions = Column(JSON, default=list)
    auto_save_enabled = Column(Boolean, default=True)

    # External Integration
    source_type = Column(String(50), nullable=True)  # sharepoint, gdrive, upload, manual
    source_url = Column(Text, nullable=True)
    external_id = Column(String(255), nullable=True)

    # Additional data
    tags = Column(JSON, default=list)
    extra_data = Column('metadata', JSON, default=dict)

    # Relationships
    owner = relationship("User", foreign_keys=[owner_id])
    last_editor = relationship("User", foreign_keys=[last_edited_by])
    team = relationship("Team")
    template = relationship("Document", remote_side="Document.id")

    permissions = relationship("DocumentPermission", back_populates="document", cascade="all, delete-orphan")
    content_versions = relationship("DocumentContent", back_populates="document", cascade="all, delete-orphan")
    shares = relationship("DocumentShare", back_populates="document", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Document(title='{self.title}', status='{self.status}')>"


class DocumentPermission(BaseModel):
    """
    Document-level permissions for users and teams.
    Controls read, write, and admin access.
    """
    __tablename__ = 'document_permissions'

    # Foreign Keys
    document_id = Column(UUID(as_uuid=True), ForeignKey('documents.id', ondelete='CASCADE'), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    team_id = Column(UUID(as_uuid=True), ForeignKey('teams.id'), nullable=True)

    # Permission Level
    permission_type = Column(String(50), nullable=False)  # read, write, admin, comment
    can_read = Column(Boolean, default=True)
    can_write = Column(Boolean, default=False)
    can_admin = Column(Boolean, default=False)
    can_comment = Column(Boolean, default=True)
    can_share = Column(Boolean, default=False)

    # Expiration
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)

    # Granted by
    granted_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)

    # Additional data
    extra_data = Column('metadata', JSON, default=dict)

    # Relationships
    document = relationship("Document", back_populates="permissions")
    user = relationship("User", foreign_keys=[user_id])
    team = relationship("Team", foreign_keys=[team_id])
    grantor = relationship("User", foreign_keys=[granted_by])

    def __repr__(self):
        target = f"user={self.user_id}" if self.user_id else f"team={self.team_id}"
        return f"<DocumentPermission(document={self.document_id}, {target}, type='{self.permission_type}')>"


class DocumentContent(BaseModel):
    """
    Version history for document content.
    Stores TipTap JSON and supports real-time collaboration.
    """
    __tablename__ = 'document_content'

    # Foreign Key
    document_id = Column(UUID(as_uuid=True), ForeignKey('documents.id', ondelete='CASCADE'), nullable=False)

    # Version Info
    version = Column(Integer, nullable=False)
    is_current = Column(Boolean, default=False)

    # Content
    content = Column(JSON, nullable=False)  # TipTap JSON structure
    plain_text = Column(Text, nullable=True)  # For search and indexing
    html_content = Column(Text, nullable=True)  # Rendered HTML

    # Statistics
    word_count = Column(Integer, default=0)
    character_count = Column(Integer, default=0)
    reading_time = Column(Integer, default=0)  # Estimated reading time in minutes

    # Author
    author_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    change_description = Column(Text, nullable=True)

    # Collaboration
    yjs_state = Column(JSON, nullable=True)  # Y.js state for real-time collaboration
    conflict_resolution = Column(JSON, nullable=True)

    # Additional data
    extra_data = Column('metadata', JSON, default=dict)

    # Relationships
    document = relationship("Document", back_populates="content_versions")
    author = relationship("User")

    def __repr__(self):
        return f"<DocumentContent(document={self.document_id}, version={self.version})>"


class DocumentShare(BaseModel):
    """
    Document sharing and public access management.
    """
    __tablename__ = 'document_shares'

    # Foreign Key
    document_id = Column(UUID(as_uuid=True), ForeignKey('documents.id', ondelete='CASCADE'), nullable=False)

    # Share Settings
    share_token = Column(String(255), unique=True, nullable=False)
    share_type = Column(String(50), nullable=False)  # public, link, password, email
    access_level = Column(String(50), nullable=False, default='read')  # read, comment, write

    # Security
    password_hash = Column(String(255), nullable=True)  # For password-protected shares
    allowed_emails = Column(JSON, default=list)  # For email-restricted shares
    allowed_domains = Column(JSON, default=list)  # For domain-restricted shares

    # Limits
    max_views = Column(Integer, nullable=True)
    current_views = Column(Integer, default=0)
    expires_at = Column(DateTime, nullable=True)

    # Status
    is_active = Column(Boolean, default=True)
    last_accessed_at = Column(DateTime, nullable=True)

    # Created by
    created_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)

    # Additional data
    extra_data = Column('metadata', JSON, default=dict)

    # Relationships
    document = relationship("Document", back_populates="shares")
    creator = relationship("User")

    def __repr__(self):
        return f"<DocumentShare(document={self.document_id}, token='{self.share_token[:8]}...', type='{self.share_type}')>"
