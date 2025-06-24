#!/usr/bin/env python3
"""
Get valid Authentik API token.
This helps you retrieve a valid API token from Authentik.
"""
import os
from dotenv import load_dotenv

load_dotenv()

print("To get a valid Authentik API token:")
print("\n1. Open Authentik Admin Interface:")
print(f"   http://127.0.0.1:9000/if/admin/")
print("\n2. Login with credentials:")
print(f"   Username: {os.getenv('AUTHENTIK_BOOTSTRAP_EMAIL', 'admin@nai.local')}")
print(f"   Password: {os.getenv('AUTHENTIK_BOOTSTRAP_PASSWORD', 'Q9KW5mqkqT5yUxQctzXN8MbB')}")
print("\n3. Navigate to:")
print("   Directory → Tokens")
print("\n4. Either:")
print("   a) Look for an existing API token")
print("   b) Create a new token:")
print("      - Click 'Create'")
print("      - Set identifier (e.g., 'api-token')")
print("      - Set user to 'akadmin' (superuser)")
print("      - Leave expiry empty for non-expiring token")
print("      - Click 'Create'")
print("\n5. Copy the token key and update your .env file:")
print("   AUTHENTIK_BOOTSTRAP_TOKEN=<your-new-token>")
print("\n6. The token format should look like:")
print("   - A long alphanumeric string")
print("   - Example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0'")

# Check if we can access the admin interface
import httpx

try:
    response = httpx.get("http://127.0.0.1:9000/if/admin/")
    if response.status_code == 200:
        print("\n✅ Authentik admin interface is accessible!")
    else:
        print(f"\n⚠️  Admin interface returned status: {response.status_code}")
except Exception as e:
    print(f"\n❌ Cannot access admin interface: {e}")
    print("   Make sure Authentik is running")