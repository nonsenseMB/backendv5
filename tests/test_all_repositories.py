"""
Extended tests for all repositories.
"""
import asyncio
from datetime import datetime, timedelta
from uuid import uuid4

from infrastructure.database.session import get_async_session, init_db
from infrastructure.database.unit_of_work import UnitOfWork


async def test_complete_workflow():
    """Test a complete workflow with all repositories."""
    print("Starting complete workflow test...")
    
    # Initialize database
    await init_db()
    
    async for session in get_async_session():
        async with UnitOfWork(session) as uow:
            # 1. Create tenant
            tenant = await uow.tenants.create(
                name="Complete Test Corp",
                slug="complete-test",
                plan_type="enterprise",
                is_active=True
            )
            print(f"✓ Created tenant: {tenant.name}")
            
            # Switch to tenant context
            tenant_uow = uow.with_tenant(tenant.id)
            
            # 2. Create users
            user1 = await uow.users.create(
                external_id="ext_001",
                email="admin@test.com",
                username="admin",
                full_name="Admin User",
                is_active=True
            )
            
            user2 = await uow.users.create(
                external_id="ext_002", 
                email="member@test.com",
                username="member",
                full_name="Member User",
                is_active=True
            )
            print(f"✓ Created users: {user1.email}, {user2.email}")
            
            # 3. Add users to tenant
            tenant_user1 = await tenant_uow.tenant_users.add_user_to_tenant(
                user_id=user1.id,
                role="admin"
            )
            tenant_user2 = await tenant_uow.tenant_users.add_user_to_tenant(
                user_id=user2.id,
                role="member"
            )
            print(f"✓ Added users to tenant with roles: {tenant_user1.role}, {tenant_user2.role}")
            
            # 4. Create LLM provider
            llm_provider = await tenant_uow.llm_providers.create(
                provider_type="openai",
                display_name="OpenAI",
                created_by=user1.id,
                is_active=True,
                is_default=True
            )
            print(f"✓ Created LLM provider: {llm_provider.display_name}")
            
            # 5. Add API key
            api_key = await uow.llm_api_keys.create_api_key(
                provider_id=llm_provider.id,
                key_name="Production Key",
                encrypted_key="encrypted_api_key_here",
                created_by=user1.id,
                key_hint="...1234"
            )
            print(f"✓ Created API key: {api_key.key_name}")
            
            # 6. Create agent
            agent = await tenant_uow.agents.create(
                name="Support Assistant",
                display_name="Support Bot",
                agent_type="general",
                description="Helps with customer support",
                created_by=user1.id
            )
            print(f"✓ Created agent: {agent.name}")
            
            # 7. Create team
            team = await tenant_uow.teams.create_team(
                name="Support Team",
                slug="support-team",
                created_by=user1.id,
                description="Customer support team"
            )
            print(f"✓ Created team: {team.name}")
            
            # 8. Add members to team
            team_member1 = await uow.team_members.add_member(
                team_id=team.id,
                user_id=user1.id,
                role="owner"
            )
            team_member2 = await uow.team_members.add_member(
                team_id=team.id,
                user_id=user2.id,
                role="member",
                invited_by=user1.id
            )
            print(f"✓ Added team members: {team_member1.role}, {team_member2.role}")
            
            # 9. Create conversation
            conversation = await tenant_uow.conversations.create(
                user_id=user1.id,
                team_id=team.id,
                title="Support Ticket #001",
                agent_id=agent.id,
                llm_provider_id=llm_provider.id
            )
            print(f"✓ Created conversation: {conversation.title}")
            
            # 10. Add messages
            message1 = await uow.messages.create_message(
                conversation_id=conversation.id,
                role="user",
                content="I need help with my account"
            )
            message2 = await uow.messages.create_message(
                conversation_id=conversation.id,
                role="assistant",
                content="I'd be happy to help! Can you describe the issue?",
                model="gpt-4"
            )
            print(f"✓ Created {len([message1, message2])} messages")
            
            # 11. Create user preferences (only PostgreSQL memory-related data)
            # Note: Actual memory/embeddings would be stored in vector DB (Milvus/Chroma)
            print(f"✓ Skipped vector memory creation (belongs in Milvus/Chroma, not PostgreSQL)")
            
            # 12. Create user preferences
            preferences = await uow.user_preferences.create_or_update_preferences(
                user_id=user1.id,
                ai_preferences={"preferred_model": "gpt-4"},
                interface_preferences={"theme": "dark", "language": "en"}
            )
            print(f"✓ Created user preferences")
            
            # 13. Memory sharing would be handled by vector DB service
            print(f"✓ Skipped memory sharing (handled by vector DB service, not PostgreSQL)")
            
            # 14. Test complex queries
            print("\n--- Testing Complex Queries ---")
            
            # Get user's teams
            user_teams = await tenant_uow.teams.get_user_teams(user1.id)
            print(f"✓ User1 is member of {len(user_teams)} teams")
            
            # Get conversation messages
            messages = await uow.messages.get_conversation_messages(conversation.id)
            print(f"✓ Conversation has {len(messages)} messages")
            
            # Get team members
            team_members = await uow.team_members.get_team_members(team.id)
            print(f"✓ Team has {len(team_members)} members")
            
            # Vector memories would be queried from vector DB, not PostgreSQL
            print(f"✓ Vector memories would be queried from vector DB (Milvus/Chroma)")
            
            # Get active LLM providers
            active_providers = await tenant_uow.llm_providers.get_active_providers()
            print(f"✓ Tenant has {len(active_providers)} active LLM providers")
            
            # Test search functionality
            search_results = await tenant_uow.agents.search_agents("support")
            print(f"✓ Found {len(search_results)} agents matching 'support'")
            
            print("\n🎉 Complete workflow test passed!")
            
        # Session is automatically committed here
        break


async def main():
    """Run the complete test."""
    try:
        await test_complete_workflow()
        print("\n✅ All extended tests completed successfully!")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())