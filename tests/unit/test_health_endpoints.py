"""Tests for health check endpoints."""
import pytest
from fastapi.testclient import TestClient

from src.main import app


class TestHealthEndpoints:
    """Test health check functionality."""

    def test_health_endpoint_response_structure(self, client: TestClient):
        """Test comprehensive health endpoint structure."""
        response = client.get("/health")
        assert response.status_code == 200
        
        data = response.json()
        
        # Check required fields
        assert "status" in data
        assert "timestamp" in data
        assert "application" in data
        assert "system" in data
        assert "gdpr_compliance" in data
        assert "logging" in data
        
        # Check application info
        app_info = data["application"]
        assert "name" in app_info
        assert "version" in app_info
        assert "environment" in app_info

    def test_health_endpoint_system_metrics(self, client: TestClient):
        """Test system metrics in health endpoint."""
        response = client.get("/health")
        data = response.json()
        
        system = data["system"]
        assert "cpu_percent" in system
        assert "memory" in system
        assert "disk" in system
        
        # Check memory structure
        memory = system["memory"]
        assert "total_mb" in memory
        assert "available_mb" in memory
        assert "percent_used" in memory
        
        # Check disk structure
        disk = system["disk"]
        assert "total_gb" in disk
        assert "free_gb" in disk
        assert "percent_used" in disk

    def test_health_endpoint_gdpr_compliance(self, client: TestClient):
        """Test GDPR compliance information in health endpoint."""
        response = client.get("/health")
        data = response.json()
        
        gdpr = data["gdpr_compliance"]
        assert "pii_filtering_enabled" in gdpr
        assert "log_retention_days" in gdpr
        assert "tamper_protection" in gdpr
        assert "status" in gdpr
        
        # Check compliance status
        assert gdpr["status"] in ["compliant", "non_compliant"]
        assert isinstance(gdpr["pii_filtering_enabled"], bool)
        assert isinstance(gdpr["log_retention_days"], int)

    def test_health_endpoint_logging_status(self, client: TestClient):
        """Test logging status in health endpoint."""
        response = client.get("/health")
        data = response.json()
        
        logging = data["logging"]
        assert "log_directory_exists" in logging
        
        if logging["log_directory_exists"]:
            assert "log_files_count" in logging
            assert "total_log_size_mb" in logging
        else:
            assert "status" in logging
            assert "message" in logging

    def test_health_simple_endpoint(self, client: TestClient):
        """Test simple health endpoint for load balancers."""
        response = client.get("/health/simple")
        assert response.status_code == 200
        
        data = response.json()
        assert "status" in data
        assert "timestamp" in data
        assert data["status"] == "ok"

    def test_health_endpoint_status_values(self, client: TestClient):
        """Test possible health status values."""
        response = client.get("/health")
        data = response.json()
        
        # Status should be one of expected values
        assert data["status"] in ["healthy", "degraded", "unhealthy"]

    def test_health_endpoint_performance(self, client: TestClient):
        """Test health endpoint response time."""
        import time
        
        start_time = time.time()
        response = client.get("/health")
        end_time = time.time()
        
        response_time = end_time - start_time
        
        assert response.status_code == 200
        assert response_time < 5.0  # Should respond within 5 seconds

    def test_health_simple_performance(self, client: TestClient):
        """Test simple health endpoint is faster."""
        import time
        
        start_time = time.time()
        response = client.get("/health/simple")
        end_time = time.time()
        
        response_time = end_time - start_time
        
        assert response.status_code == 200
        assert response_time < 1.0  # Should be very fast

    def test_health_endpoint_error_handling(self, client: TestClient):
        """Test health endpoint handles errors gracefully."""
        # This test ensures the endpoint doesn't crash even if some checks fail
        response = client.get("/health")
        
        # Should always return a response, even if some checks fail
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        
        # If there are errors, they should be in the response
        if data["status"] == "unhealthy":
            assert "error" in data

    def test_health_warnings_detection(self, client: TestClient):
        """Test that health endpoint detects and reports warnings."""
        response = client.get("/health")
        data = response.json()
        
        # If status is degraded, there should be warnings
        if data["status"] == "degraded":
            assert "warnings" in data
            assert isinstance(data["warnings"], list)
            assert len(data["warnings"]) > 0