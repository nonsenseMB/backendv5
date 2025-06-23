import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient

from src.main import app


class TestE2EUserWorkflows:
    """End-to-end tests simulating complete user workflows."""

    def test_new_user_onboarding_flow(self, client: TestClient):
        """Test complete flow for a new user discovering the API."""
        # Step 1: User visits root to discover API
        root_response = client.get("/")
        assert root_response.status_code == 200
        api_info = root_response.json()
        
        # Verify API is running
        assert api_info["status"] == "running"
        app_name = api_info["name"]
        app_version = api_info["version"]
        
        # Step 2: User checks health status before using API
        health_response = client.get("/health")
        assert health_response.status_code == 200
        assert health_response.json()["status"] == "healthy"
        
        # Step 3: User explores API documentation (simulated)
        # In a real app, this would be /docs or /redoc
        docs_response = client.get("/docs")
        # FastAPI automatically provides /docs
        assert docs_response.status_code == 200

    def test_api_monitoring_workflow(self, client: TestClient):
        """Test workflow for monitoring API health and status."""
        # Monitoring system checks multiple times
        monitoring_results = []
        
        for i in range(3):
            # Check health
            health_resp = client.get("/health")
            monitoring_results.append({
                "iteration": i + 1,
                "health_status": health_resp.status_code,
                "health_data": health_resp.json()
            })
            
            # Check root endpoint for metadata
            root_resp = client.get("/")
            monitoring_results[i]["api_status"] = root_resp.json()["status"]
        
        # Verify all checks passed
        for result in monitoring_results:
            assert result["health_status"] == 200
            assert result["health_data"]["status"] == "healthy"
            assert result["api_status"] == "running"

    @pytest.mark.asyncio
    async def test_concurrent_users_workflow(self, async_client: AsyncClient):
        """Test multiple users accessing the API concurrently."""
        import asyncio
        
        async def user_workflow(user_id: int):
            """Simulate a single user's workflow."""
            # User checks API info
            root_resp = await async_client.get("/")
            assert root_resp.status_code == 200
            
            # User checks health
            health_resp = await async_client.get("/health")
            assert health_resp.status_code == 200
            
            return {
                "user_id": user_id,
                "api_info": root_resp.json(),
                "health": health_resp.json()
            }
        
        # Simulate 10 concurrent users
        tasks = [user_workflow(i) for i in range(10)]
        results = await asyncio.gather(*tasks)
        
        # Verify all users got consistent responses
        first_api_info = results[0]["api_info"]
        for result in results:
            assert result["api_info"] == first_api_info
            assert result["health"]["status"] == "healthy"

    def test_error_recovery_workflow(self, client: TestClient):
        """Test how users experience error scenarios."""
        # Step 1: User tries to access non-existent resource
        error_response = client.get("/api/users/123")
        assert error_response.status_code == 404
        
        # Step 2: User checks if API is still healthy after error
        health_response = client.get("/health")
        assert health_response.status_code == 200
        assert health_response.json()["status"] == "healthy"
        
        # Step 3: User successfully accesses valid endpoint
        root_response = client.get("/")
        assert root_response.status_code == 200
        assert root_response.json()["status"] == "running"

    def test_api_versioning_workflow(self, client: TestClient):
        """Test workflow for checking API version compatibility."""
        # User checks current API version
        response = client.get("/")
        api_data = response.json()
        
        current_version = api_data["version"]
        
        # User stores version for compatibility checking
        assert current_version is not None
        assert isinstance(current_version, str)
        
        # User verifies API name hasn't changed
        assert api_data["name"] == "Backend v5"

    def test_cors_preflight_workflow(self, client: TestClient):
        """Test CORS preflight request workflow for browser clients."""
        # Browser sends preflight OPTIONS request
        options_response = client.options(
            "/",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "content-type"
            }
        )
        
        # Check CORS headers in response
        assert options_response.status_code == 200
        
        # Browser sends actual request
        actual_response = client.get(
            "/",
            headers={"Origin": "http://localhost:3000"}
        )
        
        assert actual_response.status_code == 200
        assert "access-control-allow-origin" in actual_response.headers