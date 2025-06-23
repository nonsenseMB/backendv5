import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.main import app, lifespan


class TestMainApp:
    """Unit tests for the main FastAPI application."""

    def test_app_instance(self):
        """Test that app is a FastAPI instance."""
        assert isinstance(app, FastAPI)

    def test_app_title(self):
        """Test that app title is correctly set from settings."""
        from src.core.config import settings
        assert app.title == settings.APP_NAME

    def test_app_version(self):
        """Test that app version is correctly set from settings."""
        from src.core.config import settings
        assert app.version == settings.APP_VERSION

    def test_cors_middleware_added(self):
        """Test that CORS middleware is added to the app."""
        middleware_classes = [m.cls.__name__ for m in app.user_middleware]
        assert "CORSMiddleware" in str(middleware_classes)

    @pytest.mark.asyncio
    async def test_lifespan_context_manager(self, capsys):
        """Test the lifespan context manager."""
        from src.core.config import settings
        
        # Test the lifespan context manager
        async with lifespan(app):
            # Check startup message
            captured = capsys.readouterr()
            assert f"Starting {settings.APP_NAME} v{settings.APP_VERSION}" in captured.out
        
        # Check shutdown message
        captured = capsys.readouterr()
        assert "Shutting down..." in captured.out


class TestRootEndpoint:
    """Unit tests for the root endpoint."""

    def test_root_endpoint_exists(self, client: TestClient):
        """Test that root endpoint exists and returns 200."""
        response = client.get("/")
        assert response.status_code == 200

    def test_root_endpoint_response_structure(self, client: TestClient):
        """Test root endpoint response structure."""
        response = client.get("/")
        data = response.json()
        
        assert "name" in data
        assert "version" in data
        assert "status" in data

    def test_root_endpoint_response_values(self, client: TestClient):
        """Test root endpoint response values."""
        from src.core.config import settings
        
        response = client.get("/")
        data = response.json()
        
        assert data["name"] == settings.APP_NAME
        assert data["version"] == settings.APP_VERSION
        assert data["status"] == "running"


class TestHealthEndpoint:
    """Unit tests for the health endpoint."""

    def test_health_endpoint_exists(self, client: TestClient):
        """Test that health endpoint exists and returns 200."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_endpoint_response(self, client: TestClient):
        """Test health endpoint response."""
        response = client.get("/health")
        data = response.json()
        
        assert data == {"status": "healthy"}

    @pytest.mark.asyncio
    async def test_health_endpoint_async(self, async_client):
        """Test health endpoint with async client."""
        response = await async_client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}