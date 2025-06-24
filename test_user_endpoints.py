#!/usr/bin/env python3
"""
Test script for user profile endpoints functionality.
"""

import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.api.middleware.permissions import get_route_permission


def test_user_endpoint_permissions():
    """Test user endpoint permission mapping."""
    print("Testing user endpoint permissions...")
    
    test_cases = [
        # User profile endpoints (should be None - no permission required for self-service)
        ("GET", "/api/v1/users/me", None),
        ("PUT", "/api/v1/users/me", None),
        ("DELETE", "/api/v1/users/me", None),
        
        # User preferences endpoints
        ("GET", "/api/v1/users/me/preferences", None),
        ("PUT", "/api/v1/users/me/preferences", None),
        ("GET", "/api/v1/users/me/preferences/language", None),
        ("PUT", "/api/v1/users/me/preferences/language", None),
        ("GET", "/api/v1/users/me/preferences/ai", None),
        ("PUT", "/api/v1/users/me/preferences/ai", None),
        ("GET", "/api/v1/users/me/preferences/notifications", None),
        ("PUT", "/api/v1/users/me/preferences/notifications", None),
        
        # Tenant management endpoints
        ("GET", "/api/v1/users/me/tenants", None),
        ("GET", "/api/v1/users/me/tenant/current", None),
        ("POST", "/api/v1/users/me/tenant/switch", None),
        ("GET", "/api/v1/users/me/tenant/available", None),
        
        # Permission endpoints for comparison
        ("GET", "/api/v1/permissions/roles", "role.read"),
        ("POST", "/api/v1/permissions/roles", "role.create"),
    ]
    
    all_passed = True
    
    for method, path, expected_permission in test_cases:
        actual_permission = get_route_permission(method, path)
        
        if actual_permission == expected_permission:
            status = "✅" if expected_permission is None else f"✅ (requires: {expected_permission})"
            print(f"{status} {method:6} {path}")
        else:
            print(f"❌ {method:6} {path} -> Expected: {expected_permission}, Got: {actual_permission}")
            all_passed = False
    
    if all_passed:
        print("\n🎉 All user endpoint permission tests passed!")
    else:
        print("\n❌ Some user endpoint permission tests failed!")
    
    return all_passed


def test_user_schemas():
    """Test user schema imports and validation."""
    print("\nTesting user schema imports...")
    
    try:
        from src.api.v1.users.schemas import (
            UserProfileResponse,
            UserProfileUpdate,
            UserPreferencesResponse,
            UserPreferencesUpdate,
            NotificationPreferences,
            AIPreferences,
            PrivacySettings,
            UserTenantInfo,
            AccountDeletionRequest,
            AccountDeletionResponse
        )
        
        print("✅ All user schemas imported successfully")
        
        # Test schema validation
        ai_prefs = AIPreferences(temperature=0.8, max_tokens=2048)
        print(f"✅ AI preferences schema: temperature={ai_prefs.temperature}, max_tokens={ai_prefs.max_tokens}")
        
        notification_prefs = NotificationPreferences(email_notifications=False)
        print(f"✅ Notification preferences schema: email_notifications={notification_prefs.email_notifications}")
        
        # Test account deletion validation
        try:
            deletion_request = AccountDeletionRequest(confirmation="WRONG", reason="Test")
            print("❌ Account deletion should have failed with wrong confirmation")
            return False
        except ValueError:
            print("✅ Account deletion properly validates confirmation")
        
        deletion_request = AccountDeletionRequest(confirmation="DELETE", reason="Test deletion")
        print(f"✅ Account deletion with correct confirmation: {deletion_request.confirmation}")
        
        return True
        
    except ImportError as e:
        print(f"❌ Failed to import user schemas: {e}")
        return False
    except Exception as e:
        print(f"❌ Schema validation error: {e}")
        return False


def test_endpoint_imports():
    """Test user endpoint imports."""
    print("\nTesting user endpoint imports...")
    
    try:
        from src.api.v1.users.me_endpoints import router as me_router
        from src.api.v1.users.preferences_endpoints import router as prefs_router
        from src.api.v1.users.tenant_endpoints import router as tenant_router
        from src.api.v1.users.router import router as main_router
        
        print("✅ All user endpoint routers imported successfully")
        
        # Check router configurations
        print(f"✅ Me router prefix: {me_router.prefix}")
        print(f"✅ Preferences router prefix: {prefs_router.prefix}")
        print(f"✅ Tenant router prefix: {tenant_router.prefix}")
        print(f"✅ Main users router prefix: {main_router.prefix}")
        
        return True
        
    except ImportError as e:
        print(f"❌ Failed to import user endpoints: {e}")
        return False


def main():
    """Run all tests."""
    print("User Profile Endpoints Test Suite")
    print("=" * 50)
    
    # Test endpoint permissions
    permissions_passed = test_user_endpoint_permissions()
    
    # Test schema imports and validation
    schemas_passed = test_user_schemas()
    
    # Test endpoint imports
    endpoints_passed = test_endpoint_imports()
    
    # Final result
    print("\n" + "=" * 50)
    if permissions_passed and schemas_passed and endpoints_passed:
        print("🎉 All tests passed! User profile endpoints are working correctly.")
        print("\nImplemented endpoints:")
        print("- GET    /api/v1/users/me                      (User profile)")
        print("- PUT    /api/v1/users/me                      (Update profile)")
        print("- DELETE /api/v1/users/me                      (Request deletion)")
        print("- GET    /api/v1/users/me/preferences          (Get preferences)")
        print("- PUT    /api/v1/users/me/preferences          (Update preferences)")
        print("- GET    /api/v1/users/me/preferences/*        (Specific preferences)")
        print("- PUT    /api/v1/users/me/preferences/*        (Update specific preferences)")
        print("- GET    /api/v1/users/me/tenants              (List user tenants)")
        print("- GET    /api/v1/users/me/tenant/current       (Current tenant info)")
        print("- POST   /api/v1/users/me/tenant/switch        (Switch tenant)")
        print("- GET    /api/v1/users/me/tenant/available     (Available tenants)")
        return 0
    else:
        print("❌ Some tests failed. Please check the implementation.")
        return 1


if __name__ == "__main__":
    sys.exit(main())