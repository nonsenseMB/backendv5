#!/usr/bin/env python3
"""
Script to test Authentik connection and basic operations.
Run this to verify your Authentik integration is working correctly.
"""
import asyncio
import os
import sys
from pathlib import Path

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.infrastructure.auth import AuthentikClient, AuthentikConfig
from src.core.logging import get_logger

logger = get_logger(__name__)


async def test_authentik_connection():
    """Test the Authentik connection and basic operations"""
    
    print("🔍 Testing Authentik Connection...\n")
    
    # Check if environment variables are set (supporting both naming conventions)
    url_var = os.getenv("AUTHENTIK_URL") or os.getenv("AUTHENTIK_PUBLIC_URL")
    token_var = os.getenv("AUTHENTIK_TOKEN") or os.getenv("AUTHENTIK_BOOTSTRAP_TOKEN")
    
    missing_vars = []
    if not url_var:
        missing_vars.append("AUTHENTIK_URL or AUTHENTIK_PUBLIC_URL")
    if not token_var:
        missing_vars.append("AUTHENTIK_TOKEN or AUTHENTIK_BOOTSTRAP_TOKEN")
    
    if missing_vars:
        print("❌ Missing required environment variables:")
        for var in missing_vars:
            print(f"   - {var}")
        print("\n💡 Set them in your .env file:")
        print("   AUTHENTIK_PUBLIC_URL=http://127.0.0.1:9000")
        print("   AUTHENTIK_BOOTSTRAP_TOKEN=your-admin-token-here")
        return False
    
    try:
        # Initialize the client
        config = AuthentikConfig()
        print(f"✅ Configuration loaded:")
        print(f"   - URL: {config.authentik_url}")
        print(f"   - Token: {'*' * 10}...{config.authentik_token[-4:]}")
        print(f"   - API Base: {config.api_base_url}")
        print(f"   - JWKS URL: {config.jwks_url}\n")
        
        async with AuthentikClient(config) as client:
            # Test 1: Health Check
            print("1️⃣ Testing health check...")
            health_ok = await client.health_check()
            if health_ok:
                print("   ✅ Authentik is accessible and responding\n")
            else:
                print("   ❌ Health check failed\n")
                return False
            
            # Test 2: Get API root - Try admin version endpoint
            print("2️⃣ Testing API access...")
            try:
                # Try the admin version endpoint
                api_response = await client.get("/admin/version/")
                print(f"   ✅ API Version: {api_response.get('version_current', 'Unknown')}")
                print(f"   ✅ API Status: Connected\n")
            except Exception as e:
                # If that fails, just verify we can make any API call
                try:
                    await client.get("/core/users/?page_size=1")
                    print(f"   ✅ API Status: Connected (version check failed but API works)\n")
                except Exception as e2:
                    print(f"   ❌ API access failed: {e2}\n")
                    return False
            
            # Test 3: List users (paginated)
            print("3️⃣ Testing user listing...")
            try:
                users_response = await client.get_users(page_size=5)
                user_count = users_response.get('pagination', {}).get('count', 0)
                users = users_response.get('results', [])
                
                print(f"   ✅ Total users: {user_count}")
                print(f"   ✅ Retrieved {len(users)} users in this page")
                
                if users:
                    print("   📋 Sample users:")
                    for user in users[:3]:  # Show first 3 users
                        print(f"      - {user.get('username')} ({user.get('email', 'No email')})")
                print()
            except Exception as e:
                print(f"   ❌ User listing failed: {e}\n")
                return False
            
            # Test 4: List applications
            print("4️⃣ Testing application listing...")
            try:
                apps_response = await client.get_applications()
                apps = apps_response.get('results', [])
                
                print(f"   ✅ Found {len(apps)} applications")
                if apps:
                    print("   📋 Applications:")
                    for app in apps:
                        print(f"      - {app.get('name')} (slug: {app.get('slug')})")
                print()
            except Exception as e:
                print(f"   ❌ Application listing failed: {e}\n")
                return False
            
            # Test 5: List groups
            print("5️⃣ Testing group listing...")
            try:
                groups_response = await client.get_groups(page_size=5)
                groups = groups_response.get('results', [])
                
                print(f"   ✅ Found {len(groups)} groups")
                if groups:
                    print("   📋 Groups:")
                    for group in groups[:3]:  # Show first 3 groups
                        print(f"      - {group.get('name')}")
                print()
            except Exception as e:
                print(f"   ❌ Group listing failed: {e}\n")
                # This is not critical, continue
            
            print("✅ All tests passed! Authentik integration is working correctly.")
            return True
            
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        logger.exception("Failed to test Authentik connection")
        return False


async def test_specific_user(username: str):
    """Test fetching a specific user"""
    print(f"\n🔍 Looking for user: {username}")
    
    try:
        config = AuthentikConfig()
        async with AuthentikClient(config) as client:
            # Search for user
            users_response = await client.get_users(search=username)
            users = users_response.get('results', [])
            
            if users:
                user = users[0]
                print(f"✅ Found user:")
                print(f"   - ID: {user.get('pk')}")
                print(f"   - Username: {user.get('username')}")
                print(f"   - Email: {user.get('email', 'No email')}")
                print(f"   - Active: {user.get('is_active')}")
                print(f"   - Groups: {len(user.get('groups_obj', []))} groups")
                
                # Get full user details
                if user.get('pk'):
                    full_user = await client.get_user(str(user['pk']))
                    print(f"   - Last login: {full_user.get('last_login', 'Never')}")
            else:
                print(f"❌ User '{username}' not found")
                
    except Exception as e:
        print(f"❌ Error fetching user: {e}")


async def main():
    """Main test function"""
    print("=" * 60)
    print("Authentik Integration Test")
    print("=" * 60)
    print()
    
    # Run basic connection tests
    success = await test_authentik_connection()
    
    # If you want to test a specific user, uncomment this:
    # if success:
    #     await test_specific_user("akadmin")
    
    return success


if __name__ == "__main__":
    # Load environment variables from .env file
    from dotenv import load_dotenv
    load_dotenv()
    
    # Run the tests
    success = asyncio.run(main())
    sys.exit(0 if success else 1)