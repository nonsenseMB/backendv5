#!/usr/bin/env python3
"""Quick test to verify Authentik is running and accessible"""
import httpx
import sys
import os
from dotenv import load_dotenv

load_dotenv()

def test_authentik():
    url = os.getenv("AUTHENTIK_URL", "http://127.0.0.1:9000")
    token = os.getenv("AUTHENTIK_TOKEN")
    
    print(f"Testing Authentik at: {url}")
    
    if not token:
        print("❌ AUTHENTIK_TOKEN not set in environment")
        return False
    
    # Test 1: Check if Authentik is running
    try:
        response = httpx.get(f"{url}/api/v3/")
        print(f"✅ Authentik is running (status: {response.status_code})")
    except Exception as e:
        print(f"❌ Cannot connect to Authentik: {e}")
        print("\n💡 Make sure Authentik is running:")
        print("   docker-compose up -d")
        return False
    
    # Test 2: Check API authentication
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = httpx.get(f"{url}/api/v3/core/users/", headers=headers)
        if response.status_code == 200:
            print(f"✅ API authentication successful")
            data = response.json()
            print(f"   Found {data.get('pagination', {}).get('count', 0)} users")
        elif response.status_code == 401:
            print("❌ Invalid API token")
            print("\n💡 Get the correct token from Authentik admin interface:")
            print(f"   1. Go to {url}/if/admin/")
            print("   2. Navigate to Directory → Tokens")
            print("   3. Create or copy an existing API token")
        else:
            print(f"❌ API request failed: {response.status_code}")
    except Exception as e:
        print(f"❌ API test failed: {e}")
        return False
    
    return True

if __name__ == "__main__":
    success = test_authentik()
    sys.exit(0 if success else 1)