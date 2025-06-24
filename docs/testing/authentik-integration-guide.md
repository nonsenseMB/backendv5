# Complete Authentik Integration Testing Guide

## Overview
This guide provides step-by-step instructions to verify the Authentik integration is working correctly.

## Step 1: Verify Authentik is Running

```bash
# Check if Authentik is accessible
curl http://127.0.0.1:9000/api/v3/
```

Expected: You should get a response (even if it's an authentication error).

## Step 2: Get a Valid API Token

The bootstrap token in the .env file (`AUTHENTIK_BOOTSTRAP_TOKEN`) might be expired or invalid. You need to get a fresh token:

1. **Access Authentik Admin Interface**
   ```
   http://127.0.0.1:9000/if/admin/
   ```

2. **Login with these credentials** (from your .env):
   - Username: `admin@nai.local`
   - Password: `Q9KW5mqkqT5yUxQctzXN8MbB`

3. **Navigate to Directory → Tokens**

4. **Create or find an API token**:
   - If there's an existing token, copy its key
   - To create a new one:
     - Click "Create"
     - Identifier: `backend-api-token`
     - User: `akadmin` (the superuser)
     - Leave expiry empty
     - Click "Create"
     - Copy the generated token key

5. **Update your .env file**:
   ```bash
   AUTHENTIK_BOOTSTRAP_TOKEN=<your-new-token-key>
   ```

## Step 3: Verify Token Works

Test the token with curl:

```bash
# Replace YOUR_TOKEN with the actual token
curl -H "Authorization: Bearer YOUR_TOKEN" \
     "http://127.0.0.1:9000/api/v3/core/users/?page_size=1" | python -m json.tool
```

Expected: You should see a JSON response with user data.

## Step 4: Test the Integration

Run the comprehensive test:

```bash
python scripts/test_authentik_connection.py
```

Expected output:
```
✅ Configuration loaded
✅ Authentik is accessible and responding
✅ API Status: Connected
✅ Total users: X
✅ Found X applications
✅ All tests passed!
```

## Step 5: Test Specific Features

### Test User Lookup
```python
python scripts/manual_test_authentik.py
```

### Test in Python REPL
```python
import asyncio
from src.infrastructure.auth import AuthentikClient, AuthentikConfig

async def test():
    config = AuthentikConfig()
    async with AuthentikClient(config) as client:
        # List users
        users = await client.get_users()
        print(f"Found {users['pagination']['count']} users")
        
        # Get specific user details
        if users['results']:
            user_id = users['results'][0]['pk']
            user = await client.get_user(str(user_id))
            print(f"User details: {user['username']}")

asyncio.run(test())
```

## Troubleshooting

### Token Invalid/Expired Error

This is the most common issue. Solutions:
1. Get a new token from Authentik admin UI
2. Ensure the token is for a superuser (akadmin)
3. Check the token hasn't expired
4. Verify you're using the correct header format: `Authorization: Bearer TOKEN`

### Connection Refused

1. Check Authentik is running:
   ```bash
   docker ps | grep authentik
   ```

2. Verify ports are correct:
   - API should be on port 9000
   - Use `127.0.0.1` not `localhost`

### SSL/TLS Errors

For local development, the .env already has SSL verification disabled.

### Wrong API Endpoints

The Authentik API v3 endpoints follow this pattern:
- Users: `/api/v3/core/users/`
- Groups: `/api/v3/core/groups/`
- Applications: `/api/v3/core/applications/`

## Success Criteria

The integration is working when:
1. ✅ Health check passes
2. ✅ Can list users
3. ✅ Can fetch user details
4. ✅ Can list applications
5. ✅ No authentication errors

## Next Steps

Once verified:
1. The token will be used for all API calls
2. Proceed with Task 102: JWT Token Validation
3. Set up automated tests for CI/CD