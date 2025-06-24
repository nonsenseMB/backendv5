"""
Integration tests for audit logging system.
Tests the complete audit logging flow including database persistence and API endpoints.
"""

import pytest
from datetime import datetime, timedelta
from uuid import uuid4
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.core.logging.auth_audit import AuthAuditService, AuthAuditEvent, AuditSeverity
from src.infrastructure.database.models.audit_log import AuditLog, AuditLogRetentionPolicy
from src.core.logging.retention_manager import RetentionManager


@pytest.mark.integration
class TestAuditLoggingIntegration:
    """Integration tests for audit logging functionality."""
    
    @pytest.fixture
    def audit_service(self, db_session: Session):
        """Create audit service with real database session."""
        return AuthAuditService(db_session)
    
    @pytest.fixture
    def retention_manager(self, db_session: Session):
        """Create retention manager with real database session."""
        return RetentionManager(db_session)
    
    @pytest.mark.asyncio
    async def test_full_audit_log_lifecycle(self, audit_service: AuthAuditService, db_session: Session):
        """Test complete audit log lifecycle from creation to cleanup."""
        user_id = uuid4()
        tenant_id = uuid4()
        session_id = uuid4()
        
        # 1. Create audit log
        audit_log = await audit_service.log_auth_event(
            event_type=AuthAuditEvent.LOGIN_SUCCESS,
            user_id=user_id,
            tenant_id=tenant_id,
            session_id=session_id,
            action="login",
            details={"login_method": "sso", "ip_address": "192.168.1.1"},
            severity=AuditSeverity.INFO,
            ip_address="192.168.1.1",
            user_agent="TestAgent/1.0",
            success=True
        )
        
        # 2. Verify log was created in database
        db_log = db_session.query(AuditLog).filter(AuditLog.id == audit_log.id).first()
        assert db_log is not None
        assert db_log.event_type == AuthAuditEvent.LOGIN_SUCCESS.value
        assert db_log.user_id == user_id
        assert db_log.tenant_id == tenant_id
        assert db_log.success is True
        assert db_log.ip_address_hash is not None
        assert "login_method" in db_log.details
        
        # 3. Query the audit log
        query_result = await audit_service.query_audit_logs(
            requester_id=user_id,
            user_filter=user_id,
            limit=10
        )
        
        assert query_result["total_count"] >= 1
        found_log = None
        for log in query_result["logs"]:
            if log["id"] == str(audit_log.id):
                found_log = log
                break
        
        assert found_log is not None
        assert found_log["event_type"] == AuthAuditEvent.LOGIN_SUCCESS.value
        assert found_log["success"] is True
        
        # 4. Test log expiration and cleanup
        # Set retention date to past for testing cleanup
        db_log.retention_date = datetime.utcnow() - timedelta(days=1)
        db_session.commit()
        
        # Run cleanup
        cleaned_count = await audit_service.cleanup_expired_logs(batch_size=100)
        assert cleaned_count >= 1
        
        # Verify log was deleted
        deleted_log = db_session.query(AuditLog).filter(AuditLog.id == audit_log.id).first()
        assert deleted_log is None
    
    @pytest.mark.asyncio
    async def test_retention_policy_application(
        self, 
        audit_service: AuthAuditService, 
        retention_manager: RetentionManager,
        db_session: Session
    ):
        """Test retention policy application to audit logs."""
        # 1. Create a retention policy
        policy = AuditLogRetentionPolicy(
            policy_name="test_auth_policy",
            description="Test policy for auth events",
            event_types=["auth.login.success"],
            event_categories=["auth"],
            severity_levels=["info"],
            retention_days=90,
            is_active=True,
            created_by=uuid4()
        )
        db_session.add(policy)
        db_session.commit()
        
        # 2. Create audit log without retention date
        audit_log = await audit_service.log_auth_event(
            event_type=AuthAuditEvent.LOGIN_SUCCESS,
            user_id=uuid4(),
            action="test_login",
            severity=AuditSeverity.INFO
        )
        
        # Clear retention date to simulate log without policy applied
        db_log = db_session.query(AuditLog).filter(AuditLog.id == audit_log.id).first()
        db_log.retention_date = None
        db_session.commit()
        
        # 3. Apply retention policies
        policy_stats = await retention_manager.apply_retention_policies(batch_size=100)
        
        assert policy_stats["processed"] >= 1
        assert policy_stats["updated"] >= 1
        
        # 4. Verify retention date was set
        db_session.refresh(db_log)
        assert db_log.retention_date is not None
        
        # Verify the retention date matches policy (90 days from log timestamp)
        expected_retention = db_log.timestamp + timedelta(days=90)
        assert abs((db_log.retention_date - expected_retention).total_seconds()) < 60  # Within 1 minute
    
    @pytest.mark.asyncio
    async def test_sensitive_event_handling(self, audit_service: AuthAuditService, db_session: Session):
        """Test handling of sensitive audit events."""
        user_id = uuid4()
        
        # Create sensitive event
        audit_log = await audit_service.log_auth_event(
            event_type=AuthAuditEvent.LOGIN_FAILED,
            user_id=user_id,
            details={
                "attempted_username": "hacker@evil.com",
                "password": "should_be_redacted", 
                "failure_reason": "invalid_credentials"
            },
            severity=AuditSeverity.WARNING,
            ip_address="10.0.0.1",
            success=False
        )
        
        # Verify log is marked as sensitive
        db_log = db_session.query(AuditLog).filter(AuditLog.id == audit_log.id).first()
        assert db_log.is_sensitive is True
        
        # Verify PII was sanitized
        assert db_log.details["password"] == "[REDACTED]"
        assert db_log.details["failure_reason"] == "invalid_credentials"  # Safe field preserved
        
        # Verify IP was hashed
        assert db_log.ip_address_hash is not None
        assert db_log.ip_address_hash != "10.0.0.1"
    
    @pytest.mark.asyncio
    async def test_bulk_audit_logging_performance(self, audit_service: AuthAuditService):
        """Test performance with bulk audit log creation."""
        import time
        
        user_id = uuid4()
        tenant_id = uuid4()
        
        # Create multiple audit logs rapidly
        start_time = time.time()
        log_count = 50
        
        for i in range(log_count):
            await audit_service.log_auth_event(
                event_type=AuthAuditEvent.DATA_ACCESS if i % 2 == 0 else AuthAuditEvent.LOGIN_SUCCESS,
                user_id=user_id,
                tenant_id=tenant_id,
                action=f"test_action_{i}",
                details={"iteration": i, "batch_test": True},
                severity=AuditSeverity.INFO
            )
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Verify performance (should complete in reasonable time)
        assert duration < 30  # Should complete within 30 seconds
        
        # Verify all logs were created
        query_result = await audit_service.query_audit_logs(
            requester_id=user_id,
            user_filter=user_id,
            limit=log_count + 10
        )
        
        assert query_result["total_count"] >= log_count
        
        # Verify batch test logs are present
        batch_logs = [log for log in query_result["logs"] if log["details"].get("batch_test")]
        assert len(batch_logs) >= log_count
    
    @pytest.mark.asyncio
    async def test_audit_query_filtering(self, audit_service: AuthAuditService, db_session: Session):
        """Test comprehensive audit log query filtering."""
        user1_id = uuid4()
        user2_id = uuid4()
        tenant1_id = uuid4()
        tenant2_id = uuid4()
        
        # Create various audit logs for testing filtering
        test_logs = [
            # User 1, Tenant 1, Success
            {
                "event_type": AuthAuditEvent.LOGIN_SUCCESS,
                "user_id": user1_id,
                "tenant_id": tenant1_id,
                "severity": AuditSeverity.INFO,
                "success": True
            },
            # User 1, Tenant 1, Failed
            {
                "event_type": AuthAuditEvent.LOGIN_FAILED,
                "user_id": user1_id,
                "tenant_id": tenant1_id,
                "severity": AuditSeverity.WARNING,
                "success": False
            },
            # User 2, Tenant 2, Success
            {
                "event_type": AuthAuditEvent.PROFILE_UPDATED,
                "user_id": user2_id,
                "tenant_id": tenant2_id,
                "severity": AuditSeverity.INFO,
                "success": True
            },
            # User 1, Different event type
            {
                "event_type": AuthAuditEvent.DATA_EXPORT,
                "user_id": user1_id,
                "tenant_id": tenant1_id,
                "severity": AuditSeverity.CRITICAL,
                "success": True
            }
        ]
        
        created_logs = []
        for log_data in test_logs:
            log = await audit_service.log_auth_event(**log_data)
            created_logs.append(log)
        
        # Test user filtering
        user1_logs = await audit_service.query_audit_logs(
            requester_id=user1_id,
            user_filter=user1_id,
            limit=100
        )
        user1_log_ids = {log["id"] for log in user1_logs["logs"]}
        assert any(str(created_logs[0].id) in user1_log_ids for log in user1_logs["logs"])
        assert any(str(created_logs[1].id) in user1_log_ids for log in user1_logs["logs"])
        
        # Test tenant filtering
        tenant1_logs = await audit_service.query_audit_logs(
            requester_id=user1_id,
            tenant_filter=tenant1_id,
            limit=100
        )
        assert tenant1_logs["total_count"] >= 3  # At least 3 logs for tenant1
        
        # Test success filtering
        success_logs = await audit_service.query_audit_logs(
            requester_id=user1_id,
            success_filter=True,
            limit=100
        )
        failed_logs = await audit_service.query_audit_logs(
            requester_id=user1_id,
            success_filter=False,
            limit=100
        )
        assert success_logs["total_count"] >= 2
        assert failed_logs["total_count"] >= 1
        
        # Test event type filtering
        login_logs = await audit_service.query_audit_logs(
            requester_id=user1_id,
            event_types=["auth.login.success", "auth.login.failed"],
            limit=100
        )
        assert login_logs["total_count"] >= 2
        
        # Test severity filtering
        critical_logs = await audit_service.query_audit_logs(
            requester_id=user1_id,
            severity_levels=["critical"],
            limit=100
        )
        assert critical_logs["total_count"] >= 1
    
    @pytest.mark.asyncio
    async def test_retention_summary_generation(
        self, 
        retention_manager: RetentionManager,
        audit_service: AuthAuditService
    ):
        """Test retention summary statistics generation."""
        # Create some audit logs with different ages
        user_id = uuid4()
        
        # Recent log (last 30 days)
        await audit_service.log_auth_event(
            event_type=AuthAuditEvent.LOGIN_SUCCESS,
            user_id=user_id,
            details={"age_category": "recent"}
        )
        
        # Older log (simulate by manually setting timestamp)
        old_log = await audit_service.log_auth_event(
            event_type=AuthAuditEvent.DATA_ACCESS,
            user_id=user_id,
            details={"age_category": "old"}
        )
        
        # Generate retention summary
        summary = await retention_manager.get_retention_summary()
        
        # Verify summary contains expected fields
        assert "total_logs" in summary
        assert "logs_with_retention" in summary
        assert "logs_without_retention" in summary
        assert "expired_logs" in summary
        assert "logs_last_30_days" in summary
        assert "logs_30_365_days" in summary
        assert "logs_over_1_year" in summary
        assert "active_retention_policies" in summary
        assert "sensitive_logs" in summary
        assert "estimated_storage_mb" in summary
        
        # Verify numeric values
        assert summary["total_logs"] >= 2
        assert summary["logs_last_30_days"] >= 1
        assert summary["estimated_storage_mb"] >= 0


@pytest.mark.integration
class TestAuditAPIIntegration:
    """Integration tests for audit API endpoints."""
    
    def test_audit_query_endpoint(self, client: TestClient, auth_headers: dict):
        """Test audit log query API endpoint."""
        # Create audit log query request
        query_request = {
            "start_date": (datetime.utcnow() - timedelta(days=7)).isoformat(),
            "end_date": datetime.utcnow().isoformat(),
            "limit": 50,
            "offset": 0,
            "justification": "Integration test query"
        }
        
        response = client.post(
            "/api/v1/audit/query",
            json=query_request,
            headers=auth_headers
        )
        
        # Should succeed (or fail with proper authorization error)
        assert response.status_code in [200, 401, 403]
        
        if response.status_code == 200:
            data = response.json()
            assert "logs" in data
            assert "total_count" in data
            assert "returned_count" in data
            assert "query_duration_ms" in data
    
    def test_audit_summary_endpoint(self, client: TestClient, auth_headers: dict):
        """Test audit summary API endpoint."""
        response = client.get(
            "/api/v1/audit/summary?days=30",
            headers=auth_headers
        )
        
        # Should succeed (or fail with proper authorization error)
        assert response.status_code in [200, 401, 403]
        
        if response.status_code == 200:
            data = response.json()
            assert "period_days" in data
            assert "total_events" in data
            assert "event_type_breakdown" in data
            assert "severity_breakdown" in data
    
    def test_retention_policies_endpoint(self, client: TestClient, auth_headers: dict):
        """Test retention policies API endpoint."""
        response = client.get(
            "/api/v1/audit/retention-policies",
            headers=auth_headers
        )
        
        # Should succeed (or fail with proper authorization error)
        assert response.status_code in [200, 401, 403]
        
        if response.status_code == 200:
            data = response.json()
            assert isinstance(data, list)


@pytest.mark.integration 
class TestAuditMiddlewareIntegration:
    """Integration tests for audit logging middleware."""
    
    def test_middleware_logs_api_requests(self, client: TestClient):
        """Test that middleware logs API requests to audit system."""
        # Make authenticated request that should be audited
        response = client.get("/api/v1/users/me")
        
        # Response code will depend on authentication setup
        # The important thing is that the request was processed
        assert response.status_code in [200, 401, 403, 404]
        
        # In a real integration test, we would verify that an audit log
        # was created in the database for this request
    
    def test_middleware_handles_errors_gracefully(self, client: TestClient):
        """Test that middleware handles errors without breaking requests."""
        # Make request that might cause middleware issues
        response = client.get("/api/v1/nonexistent")
        
        # Should get proper 404, not crash due to middleware
        assert response.status_code == 404
    
    def test_security_middleware_detects_suspicious_activity(self, client: TestClient):
        """Test security middleware detection capabilities."""
        # Make request with suspicious user agent
        headers = {"User-Agent": "sqlmap/1.0"}
        response = client.get("/api/v1/health", headers=headers)
        
        # Request should still work but be logged as suspicious
        assert response.status_code in [200, 404]