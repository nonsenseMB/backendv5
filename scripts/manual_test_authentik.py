#!/usr/bin/env python3
"""
Manual test script for Authentik integration.
Use this after you've obtained a valid API token.
"""
import asyncio
import os
import sys
from pathlib import Path

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv()

# For testing, you can override the token here if needed
# os.environ['AUTHENTIK_BOOTSTRAP_TOKEN'] = 'your-valid-token-here'

async def manual_test():
    """Run manual tests with current configuration"""
    
    print("🔧 Manual Authentik Test\n")
    
    # Show current configuration
    url = os.getenv('AUTHENTIK_PUBLIC_URL', 'Not set')
    token = os.getenv('AUTHENTIK_BOOTSTRAP_TOKEN', 'Not set')
    
    print(f"Current configuration:")
    print(f"  URL: {url}")
    print(f"  Token: {'*' * 10}...{token[-4:] if len(token) > 4 else token}")
    print()
    
    if url == 'Not set' or token == 'Not set':
        print("❌ Configuration missing!")
        return
    
    # Test with curl first (simpler)
    print("1️⃣ Testing with curl...")
    import subprocess
    
    curl_cmd = [
        'curl', '-s', '-w', '\\nHTTP Status: %{http_code}\\n',
        '-H', f'Authorization: Bearer {token}',
        f'{url}/api/v3/core/users/?page_size=1'
    ]
    
    result = subprocess.run(curl_cmd, capture_output=True, text=True)
    print("Response:")
    print(result.stdout[:200])  # First 200 chars
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
    print()
    
    # Now test with our client
    print("2️⃣ Testing with AuthentikClient...")
    try:
        from src.infrastructure.auth import AuthentikClient, AuthentikConfig
        
        config = AuthentikConfig()
        async with AuthentikClient(config) as client:
            # Try a simple request
            users = await client.get_users(page_size=1)
            print(f"✅ Success! Found {users.get('pagination', {}).get('count', 0)} users")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(manual_test())