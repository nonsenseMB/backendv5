import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient

from src.main import app


class TestAPIIntegration:
    """Integration tests for API endpoints with real dependencies."""

    def test_full_api_flow(self, client: TestClient):
        """Test a full API flow with multiple endpoints."""
        # First, check the root endpoint
        root_response = client.get("/")
        assert root_response.status_code == 200
        root_data = root_response.json()
        
        # Then check health endpoint
        health_response = client.get("/health")
        assert health_response.status_code == 200
        health_data = health_response.json()
        
        # Verify both endpoints return expected data
        assert root_data["status"] == "running"
        assert health_data["status"] == "healthy"

    def test_cors_headers_integration(self, client: TestClient):
        """Test CORS headers are properly set in responses."""
        # Test with an origin that's in the allowed list
        response = client.get(
            "/",
            headers={"Origin": "http://localhost:3000"}
        )
        
        assert response.status_code == 200
        assert "access-control-allow-origin" in response.headers

    def test_invalid_endpoint_handling(self, client: TestClient):
        """Test how the API handles requests to non-existent endpoints."""
        response = client.get("/non-existent-endpoint")
        assert response.status_code == 404
        assert "detail" in response.json()

    @pytest.mark.asyncio
    async def test_concurrent_requests(self, async_client: AsyncClient):
        """Test handling of concurrent requests."""
        import asyncio
        
        # Make multiple concurrent requests
        tasks = [
            async_client.get("/"),
            async_client.get("/health"),
            async_client.get("/"),
            async_client.get("/health"),
        ]
        
        responses = await asyncio.gather(*tasks)
        
        # All requests should succeed
        for response in responses:
            assert response.status_code == 200

    def test_application_metadata_consistency(self, client: TestClient):
        """Test that application metadata is consistent across endpoints."""
        from src.core.config import settings
        
        # Get root endpoint data
        root_response = client.get("/")
        root_data = root_response.json()
        
        # Verify metadata matches settings
        assert root_data["name"] == settings.APP_NAME
        assert root_data["version"] == settings.APP_VERSION

    @pytest.mark.asyncio
    async def test_lifespan_events_integration(self, capsys):
        """Test application lifespan events in integration context."""
        from src.main import lifespan
        
        # Create a test app instance
        test_app = app
        
        # Run through lifespan
        async with lifespan(test_app):
            # Application is running
            captured = capsys.readouterr()
            assert "Starting" in captured.out
        
        # Application has shut down
        captured = capsys.readouterr()
        assert "Shutting down..." in captured.out

    def test_error_handling_integration(self, client: TestClient):
        """Test error handling across the application."""
        # Test various error scenarios
        
        # 404 error
        response = client.get("/api/v1/users")
        assert response.status_code == 404
        
        # Method not allowed
        response = client.post("/health")
        assert response.status_code == 405