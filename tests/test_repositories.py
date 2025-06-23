"""
Basic tests for repository CRUD operations.
"""
import asyncio
from datetime import datetime
from uuid import uuid4

from infrastructure.database.session import get_async_session, init_db
from infrastructure.database.unit_of_work import UnitOfWork
from infrastructure.database.models.tenant import Tenant
from infrastructure.database.models.auth import User


async def test_crud_operations():
    """Test basic CRUD operations."""
    print("Starting CRUD tests...")
    
    # Initialize database
    await init_db()
    
    async for session in get_async_session():
        async with UnitOfWork(session) as uow:
            # Test Tenant CRUD
            print("\n1. Testing Tenant CRUD...")
            
            # Create
            tenant = await uow.tenants.create(
                name="Test Company",
                slug="test-company",
                plan_type="starter",
                is_active=True
            )
            print(f"   Created tenant: {tenant.name} (ID: {tenant.id})")
            
            # Read
            fetched_tenant = await uow.tenants.get(tenant.id)
            assert fetched_tenant is not None
            assert fetched_tenant.name == "Test Company"
            print(f"   Fetched tenant: {fetched_tenant.name}")
            
            # Update
            updated_tenant = await uow.tenants.update(
                tenant.id,
                plan_type="professional",
                max_users=50
            )
            assert updated_tenant.plan_type == "professional"
            print(f"   Updated tenant plan to: {updated_tenant.plan_type}")
            
            # Test User CRUD
            print("\n2. Testing User CRUD...")
            
            # Create
            user = await uow.users.create(
                external_id="auth_123456",
                email="test@example.com",
                username="testuser",
                full_name="Test User",
                is_active=True
            )
            print(f"   Created user: {user.email} (ID: {user.id})")
            
            # Get by email
            fetched_user = await uow.users.get_by_email("test@example.com")
            assert fetched_user is not None
            assert fetched_user.username == "testuser"
            print(f"   Fetched user by email: {fetched_user.username}")
            
            # Add user to tenant
            print("\n3. Testing TenantUser relationship...")
            tenant_uow = uow.with_tenant(tenant.id)
            tenant_user = await tenant_uow.tenant_users.add_user_to_tenant(
                user_id=user.id,
                role="admin"
            )
            print(f"   Added user to tenant with role: {tenant_user.role}")
            
            # Test Conversation CRUD
            print("\n4. Testing Conversation CRUD...")
            conversation = await tenant_uow.conversations.create(
                user_id=user.id,
                title="Test Conversation",
                model_settings={"model": "gpt-4"}
            )
            print(f"   Created conversation: {conversation.title}")
            
            # Add messages
            print("\n5. Testing Message CRUD...")
            message1 = await tenant_uow.messages.create_message(
                conversation_id=conversation.id,
                role="user",
                content="Hello, how are you?"
            )
            print(f"   Created message #{message1.sequence_number}: {message1.content[:30]}...")
            
            message2 = await tenant_uow.messages.create_message(
                conversation_id=conversation.id,
                role="assistant",
                content="I'm doing well, thank you! How can I help you today?",
                model="gpt-4"
            )
            print(f"   Created message #{message2.sequence_number}: {message2.content[:30]}...")
            
            # Get conversation messages
            messages = await tenant_uow.messages.get_conversation_messages(
                conversation_id=conversation.id
            )
            assert len(messages) == 2
            print(f"   Retrieved {len(messages)} messages from conversation")
            
            # Test search
            print("\n6. Testing search functionality...")
            search_results = await uow.users.search_by_name_or_email("test", limit=5)
            assert len(search_results) == 1
            print(f"   Found {len(search_results)} users matching 'test'")
            
            # Cleanup
            print("\n7. Testing deletion...")
            deleted = await tenant_uow.conversations.delete(conversation.id)
            assert deleted is True
            print("   Deleted conversation")
            
            deleted = await uow.users.delete(user.id)
            assert deleted is True
            print("   Deleted user")
            
            deleted = await uow.tenants.delete(tenant.id)
            assert deleted is True
            print("   Deleted tenant")
            
            print("\n✅ All CRUD tests passed!")
            
        # Session is automatically committed here
        break


async def test_transaction_rollback():
    """Test transaction rollback."""
    print("\n\nTesting transaction rollback...")
    
    async for session in get_async_session():
        try:
            async with UnitOfWork(session) as uow:
                # Create a tenant
                tenant = await uow.tenants.create(
                    name="Rollback Test",
                    slug="rollback-test",
                    is_active=True
                )
                print(f"Created tenant in transaction: {tenant.name}")
                
                # Force an error
                raise Exception("Simulated error!")
                
        except Exception as e:
            print(f"Transaction rolled back due to: {e}")
        
        # Verify tenant was not created
        async with UnitOfWork(session) as uow:
            tenant = await uow.tenants.get_by_slug("rollback-test")
            assert tenant is None
            print("✅ Verified: Tenant was not persisted after rollback")
        
        break


async def main():
    """Run all tests."""
    try:
        await test_crud_operations()
        await test_transaction_rollback()
        print("\n🎉 All tests completed successfully!")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())