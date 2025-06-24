"""
Integration tests for Authentik client.
These tests require a running Authentik instance with valid credentials.
"""
import os
import pytest
from dotenv import load_dotenv

from src.infrastructure.auth import AuthentikClient, AuthentikConfig

# Load environment variables
load_dotenv()

# Skip these tests if no Authentik URL is configured
pytestmark = pytest.mark.skipif(
    not os.getenv("AUTHENTIK_PUBLIC_URL"),
    reason="AUTHENTIK_PUBLIC_URL not configured"
)


@pytest.mark.asyncio
@pytest.mark.integration
class TestAuthentikIntegration:
    """Integration tests that require a live Authentik instance"""
    
    @pytest.fixture
    async def client(self):
        """Create an Authentik client for testing"""
        config = AuthentikConfig()
        async with AuthentikClient(config) as client:
            yield client
    
    async def test_health_check(self, client):
        """Test that health check works with real Authentik"""
        result = await client.health_check()
        assert result is True
    
    async def test_list_users(self, client):
        """Test listing users from Authentik"""
        users = await client.get_users(page_size=5)
        
        assert "pagination" in users
        assert "results" in users
        assert isinstance(users["results"], list)
        assert users["pagination"]["count"] >= 0
    
    async def test_get_specific_user(self, client):
        """Test getting a specific user (akadmin should always exist)"""
        # First, find akadmin user
        users = await client.get_users(search="akadmin")
        
        assert len(users["results"]) > 0
        akadmin = users["results"][0]
        assert akadmin["username"] == "akadmin"
        
        # Get full user details
        user_details = await client.get_user(str(akadmin["pk"]))
        assert user_details["username"] == "akadmin"
        assert "pk" in user_details
        assert "email" in user_details
    
    async def test_list_applications(self, client):
        """Test listing applications from Authentik"""
        apps = await client.get_applications()
        
        assert "results" in apps
        assert isinstance(apps["results"], list)
        
        # Check if our nAI applications exist
        app_slugs = [app["slug"] for app in apps["results"]]
        assert "nai-backend" in app_slugs or "nai-platform" in app_slugs
    
    async def test_list_groups(self, client):
        """Test listing groups from Authentik"""
        groups = await client.get_groups()
        
        assert "results" in groups
        assert isinstance(groups["results"], list)
    
    async def test_pagination(self, client):
        """Test pagination parameters work correctly"""
        # Get first page with 2 items
        page1 = await client.get_users(page=1, page_size=2)
        
        assert len(page1["results"]) <= 2
        assert page1["pagination"]["current"] == 1
        
        # Get second page if there are more users
        if page1["pagination"]["count"] > 2:
            page2 = await client.get_users(page=2, page_size=2)
            assert page2["pagination"]["current"] == 2
            
            # Ensure different users on different pages
            page1_ids = {u["pk"] for u in page1["results"]}
            page2_ids = {u["pk"] for u in page2["results"]}
            assert page1_ids.isdisjoint(page2_ids)
    
    async def test_search_functionality(self, client):
        """Test search functionality"""
        # Search for admin users
        results = await client.get_users(search="admin")
        
        assert "results" in results
        # Should find at least akadmin
        assert any(u["username"] == "akadmin" for u in results["results"])
    
    async def test_error_handling_invalid_user(self, client):
        """Test error handling when getting non-existent user"""
        with pytest.raises(Exception):  # Should raise AuthentikAPIError
            await client.get_user("99999999")  # Non-existent user ID