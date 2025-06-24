"""
Simple integration test for Authentik to verify the connection works.
"""
import asyncio
import os
import pytest
from dotenv import load_dotenv

from src.infrastructure.auth import AuthentikClient, AuthentikConfig

# Load environment variables
load_dotenv()


def test_authentik_connection_sync():
    """Test Authentik connection synchronously"""
    
    async def _test():
        config = AuthentikConfig()
        async with AuthentikClient(config) as client:
            # Test health check
            health = await client.health_check()
            assert health is True
            
            # Test listing users
            users = await client.get_users(page_size=2)
            assert "pagination" in users
            assert "results" in users
            assert len(users["results"]) > 0
            
            # Test getting akadmin user
            admin_search = await client.get_users(search="akadmin")
            assert len(admin_search["results"]) > 0
            assert admin_search["results"][0]["username"] == "akadmin"
            
            # Test applications
            apps = await client.get_applications()
            assert "results" in apps
            app_slugs = [app["slug"] for app in apps["results"]]
            assert any("nai" in slug for slug in app_slugs)
            
            return True
    
    # Only run if Authentik is configured
    if not os.getenv("AUTHENTIK_PUBLIC_URL"):
        pytest.skip("AUTHENTIK_PUBLIC_URL not configured")
    
    result = asyncio.run(_test())
    assert result is True


def test_authentik_performance():
    """Test Authentik client performance"""
    
    async def _test():
        import time
        
        config = AuthentikConfig()
        async with AuthentikClient(config) as client:
            # Test single request performance
            start = time.time()
            await client.health_check()
            health_time = (time.time() - start) * 1000
            print(f"\nHealth check took: {health_time:.2f}ms")
            assert health_time < 1000  # Should be under 1 second
            
            # Test multiple concurrent requests
            start = time.time()
            tasks = [client.get_users(page_size=1) for _ in range(5)]
            results = await asyncio.gather(*tasks)
            concurrent_time = (time.time() - start) * 1000
            print(f"5 concurrent requests took: {concurrent_time:.2f}ms")
            print(f"Average per request: {concurrent_time/5:.2f}ms")
            
            # All should succeed
            assert all("results" in r for r in results)
            
            return True
    
    if not os.getenv("AUTHENTIK_PUBLIC_URL"):
        pytest.skip("AUTHENTIK_PUBLIC_URL not configured")
    
    result = asyncio.run(_test())
    assert result is True


if __name__ == "__main__":
    # Can also be run directly
    print("Running Authentik integration tests...")
    test_authentik_connection_sync()
    print("✅ Connection test passed!")
    
    test_authentik_performance()
    print("✅ Performance test passed!")