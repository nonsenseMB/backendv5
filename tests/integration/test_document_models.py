"""
Integration tests for Document System models.
Tests CRUD operations, relationships, and business logic.
"""
import asyncio
from uuid import uuid4

from src.infrastructure.database.session import get_async_session, init_db
from src.infrastructure.database.unit_of_work import UnitOfWork


async def test_document_system_integration():
    """Test complete Document System integration."""
    print("🧪 Testing Document System Integration...")

    # Initialize database
    await init_db()

    async for session in get_async_session():
        async with UnitOfWork(session) as uow:
            # Setup: Create tenant and user
            print("\n1. Setting up test data...")
            tenant = await uow.tenants.create(
                name="Doc Test Company",
                slug="doc-test-company",
                plan_type="enterprise",
                is_active=True
            )

            user = await uow.users.create(
                external_id="doc_test_123",
                email="doctest@example.com",
                username="doctest",
                full_name="Doc Test User",
                is_active=True
            )

            team = await uow.with_tenant(tenant.id).teams.create(
                name="Documentation Team",
                slug="documentation-team",
                description="Team for testing docs",
                created_by=user.id
            )

            print(f"   Created tenant: {tenant.name}")
            print(f"   Created user: {user.email}")
            print(f"   Created team: {team.name}")

            # Test Document CRUD
            print("\n2. Testing Document CRUD...")
            tenant_uow = uow.with_tenant(tenant.id)

            document = await tenant_uow.documents.create(
                owner_id=user.id,
                team_id=team.id,
                title="Test Document",
                description="A test document for integration testing",
                document_type="document",
                content_type="tiptap",
                is_collaborative=True,
                tags=["test", "integration", "document"]
            )

            print(f"   Created document: {document.title} (ID: {document.id})")
            assert document.owner_id == user.id
            assert document.team_id == team.id
            assert document.status == "draft"
            assert document.version == 1

            # Test Document Content versioning
            print("\n3. Testing Document Content versioning...")

            # Create initial content
            tiptap_content = {
                "type": "doc",
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {"type": "text", "text": "This is the first version of the document."}
                        ]
                    }
                ]
            }

            content_v1 = await uow.document_content.create_new_version(
                document_id=document.id,
                author_id=user.id,
                content=tiptap_content,
                change_description="Initial version"
            )

            print(f"   Created content v{content_v1.version}: {content_v1.change_description}")
            assert content_v1.is_current == True
            assert content_v1.version == 1

            # Create second version
            tiptap_content_v2 = {
                "type": "doc",
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {"type": "text", "text": "This is the updated version with more content."}
                        ]
                    },
                    {
                        "type": "paragraph",
                        "content": [
                            {"type": "text", "text": "Added a second paragraph."}
                        ]
                    }
                ]
            }

            content_v2 = await uow.document_content.create_new_version(
                document_id=document.id,
                author_id=user.id,
                content=tiptap_content_v2,
                change_description="Added second paragraph"
            )

            print(f"   Created content v{content_v2.version}: {content_v2.change_description}")
            assert content_v2.is_current == True
            assert content_v2.version == 2

            # Verify version history
            history = await uow.document_content.get_version_history(document.id)
            assert len(history) == 2
            print(f"   Version history contains {len(history)} versions")

            # Test Document Permissions
            print("\n4. Testing Document Permissions...")

            # Create a second user
            user2 = await uow.users.create(
                external_id="doc_test_456",
                email="viewer@example.com",
                username="viewer",
                full_name="Viewer User",
                is_active=True
            )

            # Grant read permission to user2
            permission = await uow.document_permissions.grant_permission(
                document_id=document.id,
                user_id=user2.id,
                permission_type="read",
                granted_by=user.id
            )

            print(f"   Granted {permission.permission_type} permission to {user2.email}")
            assert permission.can_read == True
            assert permission.can_write == False

            # Check user access
            has_read = await uow.document_permissions.check_user_access(
                document_id=document.id,
                user_id=user2.id,
                permission_type="read"
            )

            has_write = await uow.document_permissions.check_user_access(
                document_id=document.id,
                user_id=user2.id,
                permission_type="write"
            )

            assert has_read == True
            assert has_write == False
            print(f"   User2 access check: read={has_read}, write={has_write}")

            # Test Document Sharing
            print("\n5. Testing Document Sharing...")

            share = await uow.document_shares.create(
                document_id=document.id,
                share_token=f"share_{uuid4().hex[:16]}",
                share_type="public",
                access_level="read",
                max_views=100,
                created_by=user.id
            )

            print(f"   Created public share with token: {share.share_token[:12]}...")
            assert share.access_level == "read"
            assert share.max_views == 100

            # Test share access
            fetched_share = await uow.document_shares.get_by_token(share.share_token)
            assert fetched_share is not None
            assert fetched_share.document_id == document.id

            # Increment view count
            success = await uow.document_shares.increment_view_count(share.id)
            assert success == True

            # Refresh and check view count
            await session.refresh(share)
            assert share.current_views == 1
            print(f"   Share view count incremented to: {share.current_views}")

            # Test search functionality
            print("\n6. Testing Document search...")

            # Create another document for search testing
            doc2 = await tenant_uow.documents.create(
                owner_id=user.id,
                title="Search Test Document",
                description="This document should appear in search results",
                document_type="note"
            )

            # Search by title
            search_results = await tenant_uow.documents.search_documents(
                query="Test",
                tenant_id=tenant.id,
                user_id=user.id
            )

            assert len(search_results) >= 2
            print(f"   Found {len(search_results)} documents matching 'Test'")

            # Test user documents retrieval
            user_docs = await tenant_uow.documents.get_user_documents(
                user_id=user.id,
                tenant_id=tenant.id,
                document_type="document"
            )

            assert len(user_docs) == 1  # Only the first document is type "document"
            print(f"   User has {len(user_docs)} documents of type 'document'")

            # Test team documents
            team_docs = await tenant_uow.documents.get_team_documents(
                team_id=team.id,
                tenant_id=tenant.id
            )

            assert len(team_docs) == 1  # Only first document assigned to team
            print(f"   Team has {len(team_docs)} documents")

            # Test relationship loading
            print("\n7. Testing relationship loading...")

            # Get document with all relationships
            full_doc = await tenant_uow.documents.get(
                document.id,
                load_relationships=["owner", "permissions", "content_versions"]
            )

            assert full_doc.owner.email == user.email
            assert len(full_doc.permissions) == 1
            assert len(full_doc.content_versions) == 2
            print(f"   Loaded document with owner, {len(full_doc.permissions)} permissions, {len(full_doc.content_versions)} content versions")

            print("\n✅ Document System integration tests passed!")

        break


async def test_document_collaboration_features():
    """Test advanced collaboration features."""
    print("\n🤝 Testing Document Collaboration Features...")

    async for session in get_async_session():
        async with UnitOfWork(session) as uow:
            # Setup
            tenant = await uow.tenants.create(
                name="Collab Test Company",
                slug="collab-test",
                is_active=True
            )

            users = []
            for i in range(3):
                user = await uow.users.create(
                    external_id=f"collab_user_{i}",
                    email=f"user{i}@collab.com",
                    username=f"user{i}",
                    full_name=f"Collaborator {i}",
                    is_active=True
                )
                users.append(user)

            # Create collaborative document
            tenant_uow = uow.with_tenant(tenant.id)
            doc = await tenant_uow.documents.create(
                owner_id=users[0].id,
                title="Collaborative Document",
                is_collaborative=True,
                max_collaborators=5
            )

            print(f"   Created collaborative document: {doc.title}")

            # Grant permissions to multiple users
            permissions = []
            for i, user in enumerate(users[1:], 1):
                perm_type = "write" if i == 1 else "comment"
                permission = await uow.document_permissions.grant_permission(
                    document_id=doc.id,
                    user_id=user.id,
                    permission_type=perm_type,
                    granted_by=users[0].id
                )
                permissions.append(permission)
                print(f"   Granted {perm_type} permission to user{i}")

            # Test concurrent content updates
            print("   Testing concurrent content updates...")

            # User 1 creates content
            content1 = await uow.document_content.create_new_version(
                document_id=doc.id,
                author_id=users[1].id,
                content={"type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "User 1 content"}]}]},
                change_description="Added by user 1"
            )

            # User 0 (owner) updates content
            content2 = await uow.document_content.create_new_version(
                document_id=doc.id,
                author_id=users[0].id,
                content={"type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Owner updated content"}]}]},
                change_description="Updated by owner"
            )

            # Get current content
            current = await uow.document_content.get_current_content(doc.id)
            assert current.author_id == users[0].id
            assert current.version == 2
            print(f"   Current content is version {current.version} by owner")

            # Test sharing with different access levels
            print("   Testing multi-level sharing...")

            # Public read-only share
            public_share = await uow.document_shares.create(
                document_id=doc.id,
                share_token=f"public_{uuid4().hex[:12]}",
                share_type="public",
                access_level="read",
                created_by=users[0].id
            )

            # Password-protected write share
            protected_share = await uow.document_shares.create(
                document_id=doc.id,
                share_token=f"protected_{uuid4().hex[:12]}",
                share_type="password",
                access_level="comment",
                password_hash="hashed_password_here",
                created_by=users[0].id
            )

            # Get all shares for document
            all_shares = await uow.document_shares.get_document_shares(doc.id)
            assert len(all_shares) == 2
            print(f"   Created {len(all_shares)} different share types")

            print("✅ Collaboration features test passed!")

        break


async def main():
    """Run all Document System integration tests."""
    try:
        await test_document_system_integration()
        await test_document_collaboration_features()
        print("\n🎉 All Document System integration tests completed successfully!")
        return True
    except Exception as e:
        print(f"\n❌ Document System tests failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)
