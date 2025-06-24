"""Unit tests for security headers and CORS middleware."""
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.middleware.base import BaseHTTPMiddleware

from src.api.middleware.cors import TenantAwareCORSMiddleware
from src.api.middleware.security import (
    SecurityHeadersMiddleware,
    get_csp_header,
    get_permissions_policy,
)
from src.core.config import settings


class TestSecurityHeadersMiddleware:
    """Test security headers middleware."""

    @pytest.mark.asyncio
    async def test_security_headers_added(self):
        """Test that security headers are added to responses."""
        app = FastAPI()
        
        # Add middleware
        middleware = SecurityHeadersMiddleware(app)
        
        # Mock request and call_next
        request = MagicMock(spec=Request)
        request.url.scheme = "https"
        
        async def call_next(req):
            return JSONResponse({"message": "test"})
        
        # Process request
        response = await middleware.dispatch(request, call_next)
        
        # Check security headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["X-XSS-Protection"] == "1; mode=block"
        assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
        assert "Permissions-Policy" in response.headers

    @pytest.mark.asyncio
    async def test_hsts_header_https_only(self):
        """Test that HSTS header is only added for HTTPS."""
        app = FastAPI()
        middleware = SecurityHeadersMiddleware(
            app,
            strict_transport_security="max-age=31536000"
        )
        
        # Test HTTPS request
        request = MagicMock(spec=Request)
        request.url.scheme = "https"
        
        async def call_next(req):
            return JSONResponse({"message": "test"})
        
        response = await middleware.dispatch(request, call_next)
        assert "Strict-Transport-Security" in response.headers
        
        # Test HTTP request
        request.url.scheme = "http"
        response = await middleware.dispatch(request, call_next)
        assert "Strict-Transport-Security" not in response.headers

    @pytest.mark.asyncio
    async def test_custom_security_headers(self):
        """Test custom security headers from settings."""
        app = FastAPI()
        
        # Mock custom headers in settings
        with patch.object(settings, 'SECURITY_HEADERS', {
            'X-Custom-Header': 'custom-value',
            'X-Another-Header': 'another-value'
        }):
            middleware = SecurityHeadersMiddleware(app)
            
            request = MagicMock(spec=Request)
            request.url.scheme = "https"
            
            async def call_next(req):
                return JSONResponse({"message": "test"})
            
            response = await middleware.dispatch(request, call_next)
            
            assert response.headers["X-Custom-Header"] == "custom-value"
            assert response.headers["X-Another-Header"] == "another-value"

    def test_csp_header_generation(self):
        """Test CSP header generation."""
        # Basic CSP
        csp = get_csp_header()
        assert "default-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "base-uri 'self'" in csp
        
        # CSP with nonce
        csp_with_nonce = get_csp_header(nonce="test-nonce-123")
        assert "'nonce-test-nonce-123'" in csp_with_nonce
        
        # CSP with report URI
        csp_with_report = get_csp_header(report_uri="https://example.com/csp-report")
        assert "report-uri https://example.com/csp-report" in csp_with_report

    def test_permissions_policy_generation(self):
        """Test Permissions Policy header generation."""
        # Default restrictive policy
        policy = get_permissions_policy()
        assert "camera=()" in policy
        assert "microphone=()" in policy
        assert "geolocation=()" in policy
        
        # With allowed features
        with patch.object(settings, 'ALLOW_GEOLOCATION', True):
            policy = get_permissions_policy()
            assert "geolocation=(self)" in policy


class TestTenantAwareCORSMiddleware:
    """Test tenant-aware CORS middleware."""

    @pytest.mark.asyncio
    async def test_no_origin_header(self):
        """Test request without origin header passes through."""
        app = FastAPI()
        middleware = TenantAwareCORSMiddleware(app)
        
        request = MagicMock(spec=Request)
        request.headers = {}
        request.method = "GET"
        
        response_called = False
        async def call_next(req):
            nonlocal response_called
            response_called = True
            return JSONResponse({"message": "test"})
        
        response = await middleware.dispatch(request, call_next)
        assert response_called
        assert "Access-Control-Allow-Origin" not in response.headers

    @pytest.mark.asyncio
    async def test_allowed_global_origin(self):
        """Test globally allowed origin gets CORS headers."""
        app = FastAPI()
        middleware = TenantAwareCORSMiddleware(app)
        
        # Mock global origin check
        with patch('src.api.middleware.cors.cors_config.is_origin_allowed_globally', return_value=True):
            request = MagicMock(spec=Request)
            request.headers = {"origin": "https://example.com"}
            request.method = "GET"
            
            async def call_next(req):
                return JSONResponse({"message": "test"})
            
            response = await middleware.dispatch(request, call_next)
            
            assert response.headers["Access-Control-Allow-Origin"] == "https://example.com"
            assert response.headers["Access-Control-Allow-Credentials"] == "true"

    @pytest.mark.asyncio
    async def test_preflight_request_allowed(self):
        """Test OPTIONS preflight request for allowed origin."""
        app = FastAPI()
        middleware = TenantAwareCORSMiddleware(
            app,
            allow_methods=["GET", "POST"],
            allow_headers=["Content-Type", "Authorization"]
        )
        
        with patch('src.api.middleware.cors.cors_config.is_origin_allowed_globally', return_value=True):
            request = MagicMock(spec=Request)
            request.headers = {"origin": "https://example.com"}
            request.method = "OPTIONS"
            
            # No need to call next for preflight
            async def call_next(req):
                raise Exception("Should not be called for preflight")
            
            response = await middleware.dispatch(request, call_next)
            
            assert response.status_code == 200
            assert response.headers["Access-Control-Allow-Origin"] == "https://example.com"
            assert response.headers["Access-Control-Allow-Methods"] == "GET, POST"
            assert response.headers["Access-Control-Allow-Headers"] == "Content-Type, Authorization"

    @pytest.mark.asyncio
    async def test_preflight_request_denied(self):
        """Test OPTIONS preflight request for denied origin."""
        app = FastAPI()
        middleware = TenantAwareCORSMiddleware(app)
        
        with patch('src.api.middleware.cors.cors_config.is_origin_allowed_globally', return_value=False):
            with patch('src.api.middleware.cors.cors_config.is_origin_allowed_for_tenant', return_value=False):
                request = MagicMock(spec=Request)
                request.headers = {"origin": "https://evil.com"}
                request.method = "OPTIONS"
                
                async def call_next(req):
                    raise Exception("Should not be called")
                
                response = await middleware.dispatch(request, call_next)
                
                assert response.status_code == 403
                assert isinstance(response, PlainTextResponse)

    @pytest.mark.asyncio
    async def test_tenant_specific_origin(self):
        """Test tenant-specific origin is allowed."""
        app = FastAPI()
        middleware = TenantAwareCORSMiddleware(app)
        
        # Mock tenant context and origin check
        with patch('src.api.middleware.cors.get_tenant_context', return_value="tenant-123"):
            with patch('src.api.middleware.cors.cors_config.is_origin_allowed_globally', return_value=False):
                with patch('src.api.middleware.cors.cors_config.is_origin_allowed_for_tenant', return_value=True):
                    request = MagicMock(spec=Request)
                    request.headers = {"origin": "https://tenant.example.com"}
                    request.method = "GET"
                    
                    async def call_next(req):
                        return JSONResponse({"message": "test"})
                    
                    response = await middleware.dispatch(request, call_next)
                    
                    assert response.headers["Access-Control-Allow-Origin"] == "https://tenant.example.com"

    @pytest.mark.asyncio
    async def test_vary_header_added(self):
        """Test that Vary: Origin header is added."""
        app = FastAPI()
        middleware = TenantAwareCORSMiddleware(app)
        
        with patch('src.api.middleware.cors.cors_config.is_origin_allowed_globally', return_value=True):
            request = MagicMock(spec=Request)
            request.headers = {"origin": "https://example.com"}
            request.method = "GET"
            
            # Test with existing Vary header
            async def call_next(req):
                response = JSONResponse({"message": "test"})
                response.headers["Vary"] = "Accept"
                return response
            
            response = await middleware.dispatch(request, call_next)
            assert response.headers["Vary"] == "Accept, Origin"
            
            # Test without existing Vary header
            async def call_next_no_vary(req):
                return JSONResponse({"message": "test"})
            
            response = await middleware.dispatch(request, call_next_no_vary)
            assert response.headers["Vary"] == "Origin"


class TestCORSConfig:
    """Test CORS configuration module."""

    def test_origin_validation(self):
        """Test origin validation."""
        from src.core.config.cors import cors_config
        
        # Valid origins
        assert cors_config.validate_origin("https://example.com") is True
        assert cors_config.validate_origin("http://localhost:3000") is True
        assert cors_config.validate_origin("https://sub.example.com:8080") is True
        
        # Invalid origins
        assert cors_config.validate_origin("example.com") is False  # No scheme
        assert cors_config.validate_origin("https://") is False  # No netloc
        assert cors_config.validate_origin("https://example.com/path") is False  # Has path
        assert cors_config.validate_origin("not-a-url") is False

    @pytest.mark.asyncio
    async def test_tenant_cors_caching(self):
        """Test that tenant CORS origins are cached."""
        from src.core.config.cors import cors_config, _tenant_cors_cache
        
        # Clear cache
        _tenant_cors_cache.clear()
        
        # Mock database fetch
        mock_session = AsyncMock()
        mock_uow = MagicMock()
        mock_tenant = MagicMock()
        mock_tenant.is_active = True
        mock_tenant.settings = {"cors_origins": ["https://tenant1.com"]}
        mock_tenant.domain = "tenant1.example.com"
        mock_uow.tenants.get_by_id = AsyncMock(return_value=mock_tenant)
        
        with patch('src.core.config.cors.UnitOfWork', return_value=mock_uow):
            # First call - should hit database
            origins1 = await cors_config.get_tenant_allowed_origins("tenant-1", mock_session)
            assert "https://tenant1.com" in origins1
            assert "https://tenant1.example.com" in origins1
            
            # Second call - should use cache
            origins2 = await cors_config.get_tenant_allowed_origins("tenant-1", mock_session)
            assert origins1 == origins2
            
            # Verify database was only called once
            mock_uow.tenants.get_by_id.assert_called_once()

    def test_wildcard_pattern_matching(self):
        """Test wildcard origin pattern matching."""
        from src.core.config.cors import CORSConfig
        
        # Mock settings with wildcard origins
        with patch.object(settings, 'CORS_ORIGINS', ["https://*.example.com", "http://localhost:*"]):
            config = CORSConfig()
            
            # Should match wildcards
            assert config.is_origin_allowed_globally("https://app.example.com") is True
            assert config.is_origin_allowed_globally("https://api.example.com") is True
            assert config.is_origin_allowed_globally("http://localhost:3000") is True
            assert config.is_origin_allowed_globally("http://localhost:8080") is True
            
            # Should not match
            assert config.is_origin_allowed_globally("https://example.com") is False
            assert config.is_origin_allowed_globally("https://app.sub.example.com") is False
            assert config.is_origin_allowed_globally("http://example.com") is False