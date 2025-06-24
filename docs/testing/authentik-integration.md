# Testing Authentik Integration

This guide explains how to test if the Authentik integration is working correctly.

## Prerequisites

1. **Authentik Server Running**
   - Authentik should be running on `http://127.0.0.1:9000`
   - You can verify this by opening the URL in your browser

2. **API Token**
   - You need an Authentik API token with admin privileges
   - Get this from Authentik Admin UI → Directory → Tokens

3. **Environment Variables**
   ```bash
   # Create a .env file in the project root
   AUTHENTIK_URL=http://127.0.0.1:9000
   AUTHENTIK_TOKEN=your-api-token-here
   ```

## Quick Test

Run the quick test script to verify basic connectivity:

```bash
python scripts/quick_test_authentik.py
```

Expected output:
```
Testing Authentik at: http://127.0.0.1:9000
✅ Authentik is running (status: 200)
✅ API authentication successful
   Found 2 users
```

## Comprehensive Test

Run the full integration test:

```bash
python scripts/test_authentik_connection.py
```

This will test:
1. Health check
2. API access
3. User listing
4. Application listing
5. Group listing

## Manual Testing with Python

You can also test manually:

```python
import asyncio
from src.infrastructure.auth import AuthentikClient, AuthentikConfig

async def test():
    config = AuthentikConfig()
    async with AuthentikClient(config) as client:
        # Test health check
        health = await client.health_check()
        print(f"Health check: {health}")
        
        # List users
        users = await client.get_users()
        print(f"Users: {users}")

asyncio.run(test())
```

## Unit Tests

Run the unit tests to verify the client implementation:

```bash
# Run all auth tests
pytest tests/unit/infrastructure/auth/ -v

# Run specific test file
pytest tests/unit/infrastructure/auth/test_authentik_client.py -v
```

## Integration Tests

For real integration tests against a live Authentik instance:

```bash
# Set test environment variables
export AUTHENTIK_URL=http://127.0.0.1:9000
export AUTHENTIK_TOKEN=your-test-token

# Run integration tests (to be created)
pytest tests/integration/auth/ -v -m integration
```

## Common Issues

### 1. Connection Refused
**Error**: `Cannot connect to Authentik: [Errno 61] Connection refused`

**Solution**: 
- Make sure Authentik is running
- Check if it's accessible at the configured URL
- Verify no firewall is blocking the connection

### 2. Invalid Token
**Error**: `Invalid API token`

**Solution**:
1. Go to Authentik Admin UI
2. Navigate to Directory → Tokens
3. Create a new token or copy existing one
4. Update your .env file

### 3. SSL Certificate Error
**Error**: `SSL: CERTIFICATE_VERIFY_FAILED`

**Solution**:
- For local development, set `AUTHENTIK_VERIFY_SSL=false` in .env
- For production, ensure valid SSL certificates

### 4. Wrong URL Format
**Error**: `Invalid URL format`

**Solution**:
- Use full URL including protocol: `http://127.0.0.1:9000`
- Don't include trailing slash
- Don't use `localhost` - use `127.0.0.1` as mentioned in the task

## Performance Testing

Test the client performance:

```python
import asyncio
import time
from src.infrastructure.auth import AuthentikClient, AuthentikConfig

async def performance_test():
    config = AuthentikConfig()
    async with AuthentikClient(config) as client:
        # Test response time
        start = time.time()
        await client.health_check()
        elapsed = (time.time() - start) * 1000
        print(f"Health check took: {elapsed:.2f}ms")
        
        # Test multiple requests
        start = time.time()
        tasks = [client.get_users(page_size=10) for _ in range(10)]
        await asyncio.gather(*tasks)
        elapsed = (time.time() - start) * 1000
        print(f"10 concurrent requests took: {elapsed:.2f}ms")

asyncio.run(performance_test())
```

## Next Steps

Once the basic integration is verified:
1. Proceed with Task 102: JWT Token Validation
2. Set up automated integration tests
3. Configure monitoring for the Authentik connection