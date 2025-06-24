"""
Security headers middleware for FastAPI.
Adds security headers to all responses for protection against common attacks.
"""
from typing import Dict, Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from src.core.config import settings
from src.core.logging import get_logger

logger = get_logger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all HTTP responses.
    
    This middleware adds various security headers to protect against:
    - XSS attacks
    - Clickjacking
    - MIME type sniffing
    - Mixed content
    - And more
    """
    
    def __init__(self, app, **options):
        super().__init__(app)
        self.options = options
        
        # Default security headers
        self.default_headers = {
            # Prevent MIME type sniffing
            "X-Content-Type-Options": "nosniff",
            
            # Prevent clickjacking
            "X-Frame-Options": options.get("x_frame_options", "DENY"),
            
            # Enable XSS protection (legacy browsers)
            "X-XSS-Protection": "1; mode=block",
            
            # Control Referer header
            "Referrer-Policy": options.get("referrer_policy", "strict-origin-when-cross-origin"),
            
            # Permissions Policy (replaces Feature-Policy)
            "Permissions-Policy": options.get(
                "permissions_policy",
                "geolocation=(), microphone=(), camera=(), payment=()"
            ),
        }
        
        # Optional HSTS header (only for HTTPS)
        self.hsts_header = options.get(
            "strict_transport_security",
            "max-age=31536000; includeSubDomains"
        )
        
        # Content Security Policy
        self.csp_header = options.get("content_security_policy")
        
        # Report-To header for CSP and other reporting
        self.report_to_header = options.get("report_to")
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """Add security headers to the response."""
        # Process the request
        response = await call_next(request)
        
        # Add default security headers
        for header, value in self.default_headers.items():
            if header not in response.headers:
                response.headers[header] = value
        
        # Add HSTS header for HTTPS connections
        if request.url.scheme == "https" and self.hsts_header:
            response.headers["Strict-Transport-Security"] = self.hsts_header
        
        # Add Content Security Policy if configured
        if self.csp_header and "Content-Security-Policy" not in response.headers:
            response.headers["Content-Security-Policy"] = self.csp_header
        
        # Add Report-To header if configured
        if self.report_to_header:
            response.headers["Report-To"] = self.report_to_header
        
        # Add custom headers from settings
        custom_headers = getattr(settings, "SECURITY_HEADERS", {})
        for header, value in custom_headers.items():
            if header not in response.headers:
                response.headers[header] = value
        
        return response


def get_csp_header(
    nonce: Optional[str] = None,
    report_uri: Optional[str] = None,
    report_only: bool = False
) -> str:
    """
    Generate a Content Security Policy header.
    
    Args:
        nonce: Optional nonce for inline scripts/styles
        report_uri: Optional URI for CSP violation reports
        report_only: If True, use Content-Security-Policy-Report-Only
        
    Returns:
        CSP header value
    """
    # Base CSP directives
    directives = {
        "default-src": "'self'",
        "script-src": "'self' 'unsafe-eval'" if settings.DEBUG else "'self'",
        "style-src": "'self' 'unsafe-inline'",  # Allow inline styles for now
        "img-src": "'self' data: https:",
        "font-src": "'self' data:",
        "connect-src": "'self'",
        "frame-ancestors": "'none'",
        "base-uri": "'self'",
        "form-action": "'self'",
    }
    
    # Add nonce if provided
    if nonce:
        directives["script-src"] += f" 'nonce-{nonce}'"
        directives["style-src"] = f"'self' 'nonce-{nonce}'"
    
    # Add WebSocket support if needed
    if hasattr(settings, "WEBSOCKET_URL"):
        ws_url = settings.WEBSOCKET_URL.replace("http://", "ws://").replace("https://", "wss://")
        directives["connect-src"] += f" {ws_url}"
    
    # Add report URI if provided
    if report_uri:
        directives["report-uri"] = report_uri
    
    # Build CSP string
    csp_parts = [f"{key} {value}" for key, value in directives.items()]
    return "; ".join(csp_parts)


def get_permissions_policy() -> str:
    """
    Generate a Permissions Policy header based on settings.
    
    Returns:
        Permissions Policy header value
    """
    # Default restrictive policy
    policies = {
        "accelerometer": "()",
        "camera": "()",
        "geolocation": "()",
        "gyroscope": "()",
        "magnetometer": "()",
        "microphone": "()",
        "payment": "()",
        "usb": "()",
    }
    
    # Allow certain features if configured
    if getattr(settings, "ALLOW_GEOLOCATION", False):
        policies["geolocation"] = "(self)"
    
    if getattr(settings, "ALLOW_CAMERA", False):
        policies["camera"] = "(self)"
    
    if getattr(settings, "ALLOW_MICROPHONE", False):
        policies["microphone"] = "(self)"
    
    # Build policy string
    policy_parts = [f"{key}={value}" for key, value in policies.items()]
    return ", ".join(policy_parts)


async def security_headers_middleware(request: Request, call_next):
    """
    Function-based security headers middleware for FastAPI.
    
    Can be used as @app.middleware("http") decorator.
    """
    # Create CSP header
    csp = get_csp_header(
        report_uri=getattr(settings, "CSP_REPORT_URI", None),
        report_only=getattr(settings, "CSP_REPORT_ONLY", False)
    )
    
    # Create middleware with configuration
    middleware = SecurityHeadersMiddleware(
        None,
        content_security_policy=csp,
        permissions_policy=get_permissions_policy(),
        x_frame_options=getattr(settings, "X_FRAME_OPTIONS", "DENY"),
        referrer_policy=getattr(settings, "REFERRER_POLICY", "strict-origin-when-cross-origin"),
        strict_transport_security=getattr(
            settings,
            "HSTS_HEADER",
            "max-age=31536000; includeSubDomains; preload"
        )
    )
    
    return await middleware.dispatch(request, call_next)