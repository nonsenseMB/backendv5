# Task 006: Security and Permission Tests

## Priority: CRITICAL
**Estimated Time**: 5-6 hours  
**Dependencies**: Tasks 001-002 (Pytest setup, fixtures)  
**Blocking**: Production deployment

## Why This Task is Critical

Security vulnerabilities can:
1. **Expose sensitive data** - User documents, API keys, personal info
2. **Allow unauthorized access** - Users accessing other tenants' data
3. **Enable privilege escalation** - Regular users becoming admins
4. **Cause data corruption** - SQL injection, XSS attacks
5. **Lead to compliance violations** - GDPR/DSGVO breaches

## What Needs to Be Done

### 1. SQL Injection Tests

Create `tests/security/test_sql_injection.py`:
```python
"""Test SQL injection prevention."""
import pytest
from uuid import uuid4
from sqlalchemy.exc import SQLAlchemyError
from tests.factories import UserFactory, DocumentFactory

class TestSQLInjection:
    """Test SQL injection attack prevention."""
    
    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_sql_injection_in_search(self, db_session, test_tenant):
        """Test SQL injection in search queries."""
        # Create test document
        doc = await DocumentFactory.create(
            title="Secret Document",
            tenant_id=test_tenant.id
        )
        
        # Attempt SQL injection attacks
        injection_attempts = [
            "'; DROP TABLE documents; --",
            "' OR '1'='1",
            "' UNION SELECT * FROM users --",
            "'; UPDATE documents SET tenant_id = '00000000-0000-0000-0000-000000000000' --",
            "' OR 1=1 --",
            "admin'--",
            "' OR 'a'='a",
        ]
        
        repo = DocumentRepository(db_session)
        
        for injection in injection_attempts:
            # Search should handle malicious input safely
            results = await repo.search_documents(
                tenant_id=test_tenant.id,
                query=injection
            )
            
            # Should not return all documents
            assert len(results) == 0
            
            # Database should still be intact
            check = await repo.get(doc.id)
            assert check is not None
            assert check.title == "Secret Document"
    
    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_sql_injection_in_filters(self, db_session, test_tenant):
        """Test SQL injection in filter parameters."""
        injections = [
            {"status": "'; DELETE FROM documents WHERE '1'='1"},
            {"tags": ["tag1", "'; DROP TABLE users; --"]},
            {"owner_id": "00000000-0000-0000-0000-000000000000' OR '1'='1"},
        ]
        
        repo = DocumentRepository(db_session)
        
        for injection_filter in injections:
            # Should safely handle malicious filters
            try:
                results = await repo.filter_documents(
                    tenant_id=test_tenant.id,
                    filters=injection_filter
                )
                # If no error, results should be empty
                assert len(results) == 0
            except SQLAlchemyError:
                # Some injections might cause errors, that's OK
                pass
    
    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_prepared_statements(self, db_session):
        """Verify all queries use parameterized statements."""
        # Check that raw SQL is not used
        repo = DocumentRepository(db_session)
        
        # This should use parameterized query
        user_input = "test' OR '1'='1"
        query = repo._build_search_query(user_input)
        
        # Verify query uses placeholders
        assert ":query" in str(query) or "%(query)s" in str(query)
        assert user_input not in str(query)
```

### 2. Permission Bypass Tests

Create `tests/security/test_permission_bypass.py`:
```python
"""Test permission bypass prevention."""
import pytest
from uuid import uuid4
from fastapi import HTTPException
from tests.factories import UserFactory, DocumentFactory, TenantFactory

class TestPermissionBypass:
    """Test authorization bypass prevention."""
    
    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_cross_tenant_access_denied(self, db_session):
        """Test users cannot access other tenants' data."""
        # Create two tenants
        tenant1 = await TenantFactory.create()
        tenant2 = await TenantFactory.create()
        
        # Create users in each tenant
        user1 = await UserFactory.create(tenant_id=tenant1.id)
        user2 = await UserFactory.create(tenant_id=tenant2.id)
        
        # Create document in tenant1
        doc = await DocumentFactory.create(
            tenant_id=tenant1.id,
            owner_id=user1.id,
            title="Tenant 1 Secret"
        )
        
        # User2 should not be able to access
        repo = DocumentRepository(db_session)
        
        # Direct access should fail
        with pytest.raises(PermissionDeniedError):
            await repo.get_with_tenant_check(
                document_id=doc.id,
                tenant_id=tenant2.id  # Wrong tenant
            )
        
        # Search should not return document
        results = await repo.search_documents(
            tenant_id=tenant2.id,
            query="Secret"
        )
        assert len(results) == 0
    
    @pytest.mark.asyncio
    @pytest.mark.security  
    async def test_permission_elevation_blocked(self, db_session):
        """Test users cannot elevate their permissions."""
        user = await UserFactory.create(role="user")
        admin = await UserFactory.create(role="admin", tenant_id=user.tenant_id)
        
        doc = await DocumentFactory.create(
            tenant_id=user.tenant_id,
            owner_id=admin.id
        )
        
        # Regular user tries to grant themselves permission
        perm_repo = DocumentPermissionRepository(db_session)
        
        with pytest.raises(PermissionDeniedError):
            await perm_repo.grant_permission(
                document_id=doc.id,
                user_id=user.id,
                permission="write",
                granted_by_id=user.id  # Can't grant to self
            )
    
    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_uuid_manipulation_blocked(self, db_session):
        """Test UUID manipulation is blocked."""
        user = await UserFactory.create()
        doc = await DocumentFactory.create(owner_id=user.id)
        
        # Try to access with manipulated UUIDs
        invalid_uuids = [
            "00000000-0000-0000-0000-000000000000",
            "invalid-uuid",
            "../../other-id",
            str(user.id) + "' OR '1'='1",
        ]
        
        repo = DocumentRepository(db_session)
        
        for bad_id in invalid_uuids:
            with pytest.raises((ValueError, PermissionDeniedError)):
                await repo.get(bad_id)
```

### 3. Authentication Tests

Create `tests/security/test_auth_bypass.py`:
```python
"""Test authentication bypass prevention."""
import pytest
from datetime import datetime, timedelta
import jwt
from tests.factories import UserFactory

class TestAuthBypass:
    """Test authentication security."""
    
    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_expired_token_rejected(self, client, test_user):
        """Test expired JWT tokens are rejected."""
        # Create expired token
        expired_token = create_test_token(
            user_id=test_user.id,
            expires_delta=timedelta(seconds=-1)  # Already expired
        )
        
        response = await client.get(
            "/api/v1/documents",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        
        assert response.status_code == 401
        assert "expired" in response.json()["detail"].lower()
    
    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_tampered_token_rejected(self, client, test_user):
        """Test tampered tokens are rejected."""
        valid_token = create_test_token(user_id=test_user.id)
        
        # Tamper with token
        parts = valid_token.split('.')
        tampered_payload = parts[1] + "tampered"
        tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"
        
        response = await client.get(
            "/api/v1/documents",
            headers={"Authorization": f"Bearer {tampered_token}"}
        )
        
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_token_replay_prevention(self, client, test_user):
        """Test token replay attacks are prevented."""
        token = create_test_token(user_id=test_user.id)
        
        # Use token
        response1 = await client.post(
            "/api/v1/documents",
            headers={"Authorization": f"Bearer {token}"},
            json={"title": "Test"}
        )
        assert response1.status_code == 201
        
        # Blacklist token (simulate logout)
        await blacklist_token(token)
        
        # Try to reuse token
        response2 = await client.get(
            "/api/v1/documents",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response2.status_code == 401
        assert "blacklisted" in response2.json()["detail"].lower()
    
    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_missing_required_claims(self, client):
        """Test tokens missing required claims are rejected."""
        # Token without tenant_id claim
        incomplete_token = jwt.encode(
            {"user_id": str(uuid4()), "exp": datetime.utcnow() + timedelta(hours=1)},
            "secret",
            algorithm="HS256"
        )
        
        response = await client.get(
            "/api/v1/documents",
            headers={"Authorization": f"Bearer {incomplete_token}"}
        )
        
        assert response.status_code == 401
```

### 4. Data Exposure Tests

Create `tests/security/test_data_exposure.py`:
```python
"""Test prevention of data exposure."""
import pytest
from tests.factories import DocumentFactory, UserFactory

class TestDataExposure:
    """Test sensitive data is not exposed."""
    
    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_password_never_exposed(self, client, db_session):
        """Test password hashes are never exposed in API."""
        user = await UserFactory.create(
            email="test@example.com",
            password_hash="$2b$12$secret_hash"
        )
        
        # Try various endpoints
        endpoints = [
            f"/api/v1/users/{user.id}",
            "/api/v1/users/me",
            f"/api/v1/teams/{user.team_id}/members",
        ]
        
        for endpoint in endpoints:
            response = await client.get(
                endpoint,
                headers=create_auth_headers(user)
            )
            
            if response.status_code == 200:
                data = response.json()
                # Password should never appear
                assert "password" not in str(data).lower()
                assert "secret_hash" not in str(data)
    
    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_internal_fields_not_exposed(self, client, test_user):
        """Test internal fields are not exposed."""
        doc = await DocumentFactory.create(
            owner_id=test_user.id,
            internal_notes="Internal only",
            _metadata={"internal": "data"}
        )
        
        response = await client.get(
            f"/api/v1/documents/{doc.id}",
            headers=create_auth_headers(test_user)
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Internal fields should not be exposed
        assert "internal_notes" not in data
        assert "_metadata" not in data
        assert "internal" not in str(data)
    
    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_error_messages_sanitized(self, client):
        """Test error messages don't expose system details."""
        # Trigger various errors
        error_triggers = [
            ("/api/v1/documents/invalid-uuid", 400),
            ("/api/v1/nonexistent", 404),
            ("/api/v1/documents", 401),  # No auth
        ]
        
        for endpoint, expected_status in error_triggers:
            response = await client.get(endpoint)
            assert response.status_code == expected_status
            
            error = response.json()
            # Should not expose system details
            assert "sqlalchemy" not in str(error).lower()
            assert "traceback" not in str(error).lower()
            assert "/home/" not in str(error)  # No file paths
            assert "postgres" not in str(error).lower()
```

### 5. Input Validation Tests

Create `tests/security/test_input_validation.py`:
```python
"""Test input validation security."""
import pytest
from pydantic import ValidationError

class TestInputValidation:
    """Test malicious input handling."""
    
    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_xss_prevention(self, client, auth_headers):
        """Test XSS attack prevention."""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')",
            "<iframe src='javascript:alert(\"xss\")'></iframe>",
            "<svg onload=alert('xss')>",
        ]
        
        for payload in xss_payloads:
            response = await client.post(
                "/api/v1/documents",
                headers=auth_headers,
                json={
                    "title": payload,
                    "content": {"text": payload}
                }
            )
            
            if response.status_code == 201:
                # If created, verify it's sanitized
                doc = response.json()
                assert "<script>" not in doc["title"]
                assert "javascript:" not in doc["title"]
                assert "onerror=" not in str(doc["content"])
    
    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_path_traversal_prevention(self, client, auth_headers):
        """Test path traversal attack prevention."""
        traversal_attempts = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/passwd",
            "C:\\Windows\\System32\\config\\SAM",
            "....//....//....//etc/passwd",
        ]
        
        for path in traversal_attempts:
            response = await client.post(
                "/api/v1/documents/upload",
                headers=auth_headers,
                json={"file_path": path}
            )
            
            assert response.status_code in [400, 403]
            assert "invalid" in response.json()["detail"].lower()
    
    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_size_limit_enforcement(self, client, auth_headers):
        """Test input size limits are enforced."""
        # Create oversized payload
        huge_content = "x" * (10 * 1024 * 1024)  # 10MB
        
        response = await client.post(
            "/api/v1/documents",
            headers=auth_headers,
            json={
                "title": "Test",
                "content": {"text": huge_content}
            }
        )
        
        assert response.status_code == 413  # Payload Too Large
    
    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_special_characters_handled(self, client, auth_headers):
        """Test special characters are handled safely."""
        special_inputs = [
            "test\x00null",  # Null byte
            "test\r\ninjection",  # CRLF injection
            "test%00null",  # URL encoded null
            "test%0d%0ainjection",  # URL encoded CRLF
        ]
        
        for input_str in special_inputs:
            response = await client.post(
                "/api/v1/documents",
                headers=auth_headers,
                json={"title": input_str}
            )
            
            if response.status_code == 201:
                doc = response.json()
                # Null bytes should be stripped
                assert "\x00" not in doc["title"]
                assert "%00" not in doc["title"]
```

### 6. Rate Limiting Tests

Create `tests/security/test_rate_limiting.py`:
```python
"""Test rate limiting and DoS prevention."""
import pytest
import asyncio
from datetime import datetime

class TestRateLimiting:
    """Test rate limiting enforcement."""
    
    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_api_rate_limiting(self, client, auth_headers):
        """Test API rate limits are enforced."""
        # Make many rapid requests
        responses = []
        for i in range(150):  # Exceed rate limit
            response = await client.get(
                "/api/v1/documents",
                headers=auth_headers
            )
            responses.append(response.status_code)
            
            if response.status_code == 429:  # Too Many Requests
                break
        
        # Should hit rate limit
        assert 429 in responses
        
        # Check rate limit headers
        last_response = responses[-1]
        assert "X-RateLimit-Limit" in last_response.headers
        assert "X-RateLimit-Remaining" in last_response.headers
        assert "X-RateLimit-Reset" in last_response.headers
    
    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_login_rate_limiting(self, client):
        """Test login attempts are rate limited."""
        failed_attempts = []
        
        for i in range(10):  # Many failed login attempts
            response = await client.post(
                "/api/v1/auth/login",
                json={
                    "email": "attacker@example.com",
                    "password": "wrong_password"
                }
            )
            failed_attempts.append(response.status_code)
            
            if response.status_code == 429:
                break
        
        # Should be rate limited after several failures
        assert 429 in failed_attempts
    
    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_concurrent_request_limits(self, client, auth_headers):
        """Test concurrent request limits."""
        # Try to overwhelm with concurrent requests
        async def make_request():
            return await client.get(
                "/api/v1/documents",
                headers=auth_headers
            )
        
        # Launch many concurrent requests
        tasks = [make_request() for _ in range(100)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Some should be rate limited
        status_codes = [r.status_code for r in responses if hasattr(r, 'status_code')]
        assert 429 in status_codes or 503 in status_codes
```

## Success Criteria

1. ✅ SQL injection attacks are prevented
2. ✅ Cross-tenant access is blocked
3. ✅ Authentication bypass is prevented
4. ✅ Sensitive data is never exposed
5. ✅ XSS attacks are prevented
6. ✅ Path traversal is blocked
7. ✅ Rate limiting is enforced
8. ✅ All tests pass in < 10 seconds

## Security Test Checklist

- [ ] SQL Injection (SELECT, INSERT, UPDATE, DELETE)
- [ ] NoSQL Injection (if applicable)
- [ ] XSS (Stored, Reflected, DOM-based)
- [ ] CSRF Protection
- [ ] Authentication Bypass
- [ ] Authorization Bypass
- [ ] Session Fixation
- [ ] Insecure Direct Object References
- [ ] Path Traversal
- [ ] Command Injection
- [ ] XXE (XML External Entity)
- [ ] SSRF (Server Side Request Forgery)
- [ ] Rate Limiting / DoS
- [ ] Information Disclosure
- [ ] Weak Cryptography

## Next Steps

After this task:
- Run security tests: `pytest tests/security -v -m security`
- Run with coverage: `pytest tests/security --cov=src`
- Consider security scanning tools (Bandit, Safety)
- Move on to Error Handling tests (Task 007)

## Notes

- Always test both positive and negative cases
- Use parameterized tests for multiple payloads
- Test at multiple layers (model, repo, API)
- Document any security assumptions
- Keep security tests updated with new attack vectors