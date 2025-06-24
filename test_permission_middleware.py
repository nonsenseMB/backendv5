#!/usr/bin/env python3
"""
Test script for permission middleware functionality.
"""

import asyncio
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.api.middleware.permissions import get_route_permission, ROUTE_PERMISSIONS


def test_route_permission_mapping():
    """Test route permission mapping."""
    print("Testing route permission mapping...")
    
    test_cases = [
        # Auth routes (no permissions)
        ("POST", "/api/v1/auth/token", None),
        ("POST", "/api/v1/auth/device/challenge", None),
        
        # Permission routes
        ("GET", "/api/v1/permissions/roles", "role.read"),
        ("POST", "/api/v1/permissions/roles", "role.create"),
        ("POST", "/api/v1/permissions/users/123e4567-e89b-12d3-a456-426614174000/roles", "role.assign"),
        ("DELETE", "/api/v1/permissions/users/123e4567-e89b-12d3-a456-426614174000/roles/456e7890-e89b-12d3-a456-426614174000", "role.remove"),
        
        # Future conversation routes
        ("POST", "/api/v1/conversations", "conversation.create"),
        ("GET", "/api/v1/conversations/123e4567-e89b-12d3-a456-426614174000", "conversation.read"),
        ("PUT", "/api/v1/conversations/123e4567-e89b-12d3-a456-426614174000", "conversation.update"),
        ("DELETE", "/api/v1/conversations/123e4567-e89b-12d3-a456-426614174000", "conversation.delete"),
        
        # Routes that don't exist
        ("GET", "/api/v1/nonexistent", None),
        ("POST", "/api/v1/unknown/route", None),
    ]
    
    all_passed = True
    
    for method, path, expected_permission in test_cases:
        actual_permission = get_route_permission(method, path)
        
        if actual_permission == expected_permission:
            print(f"✅ {method} {path} -> {actual_permission}")
        else:
            print(f"❌ {method} {path} -> Expected: {expected_permission}, Got: {actual_permission}")
            all_passed = False
    
    if all_passed:
        print("\n🎉 All route permission tests passed!")
    else:
        print("\n❌ Some route permission tests failed!")
    
    return all_passed


def test_bypass_routes():
    """Test bypass route logic."""
    from src.api.middleware.permissions import PermissionMiddleware
    
    print("\nTesting bypass routes...")
    
    # Mock request objects
    class MockRequest:
        def __init__(self, path: str):
            self.url = MockURL(path)
    
    class MockURL:
        def __init__(self, path: str):
            self.path = path
    
    middleware = PermissionMiddleware(None)
    
    bypass_test_cases = [
        ("/", True),
        ("/health", True),
        ("/health/simple", True),
        ("/docs", True),
        ("/redoc", True),
        ("/openapi.json", True),
        ("/api/v1/auth/token", False),  # Auth routes are handled separately
        ("/api/v1/permissions/roles", False),
        ("/unknown/route", False),
    ]
    
    all_passed = True
    
    for path, expected_bypass in bypass_test_cases:
        request = MockRequest(path)
        actual_bypass = middleware._should_bypass_permission_check(request)
        
        if actual_bypass == expected_bypass:
            print(f"✅ {path} -> Bypass: {actual_bypass}")
        else:
            print(f"❌ {path} -> Expected bypass: {expected_bypass}, Got: {actual_bypass}")
            all_passed = False
    
    if all_passed:
        print("\n🎉 All bypass route tests passed!")
    else:
        print("\n❌ Some bypass route tests failed!")
    
    return all_passed


def print_route_permissions_summary():
    """Print summary of all configured route permissions."""
    print("\nConfigured Route Permissions:")
    print("=" * 50)
    
    for (method, route_pattern), permission in ROUTE_PERMISSIONS.items():
        permission_str = permission if permission else "None (public)"
        print(f"{method:8} {route_pattern:50} -> {permission_str}")
    
    print(f"\nTotal routes configured: {len(ROUTE_PERMISSIONS)}")


def main():
    """Run all tests."""
    print("Permission Middleware Test Suite")
    print("=" * 40)
    
    # Test route permission mapping
    route_test_passed = test_route_permission_mapping()
    
    # Test bypass routes
    bypass_test_passed = test_bypass_routes()
    
    # Print summary
    print_route_permissions_summary()
    
    # Final result
    print("\n" + "=" * 40)
    if route_test_passed and bypass_test_passed:
        print("🎉 All tests passed! Permission middleware is working correctly.")
        return 0
    else:
        print("❌ Some tests failed. Please check the middleware configuration.")
        return 1


if __name__ == "__main__":
    sys.exit(main())