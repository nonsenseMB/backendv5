"""
Unit tests for User Session Database Models.
Tests session lifecycle, activity tracking, and security event models.
"""

from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from src.infrastructure.database.models.user_session import (
    UserSession,
    SessionActivity,
    SessionSecurityEvent
)


class TestUserSession:
    """Test UserSession model functionality."""

    @pytest.fixture
    def user_session_data(self):
        """Base data for creating user sessions."""
        return {
            'user_id': uuid4(),
            'tenant_id': uuid4(),
            'device_id': uuid4(),
            'authentik_session_id': 'auth_session_123',
            'ip_address_hash': 'abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234',
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'client_info': {'browser': 'Chrome', 'version': '91.0', 'os': 'Windows'},
            'expires_at': datetime.utcnow() + timedelta(hours=24),
            'session_type': 'web',
            'login_method': 'sso',
            'session_data': {'theme': 'dark', 'language': 'en'}
        }

    def test_user_session_creation(self, user_session_data):
        """Test UserSession model creation."""
        session = UserSession(**user_session_data)

        assert session.user_id == user_session_data['user_id']
        assert session.tenant_id == user_session_data['tenant_id']
        assert session.device_id == user_session_data['device_id']
        assert session.authentik_session_id == user_session_data['authentik_session_id']
        assert session.ip_address_hash == user_session_data['ip_address_hash']
        assert session.user_agent == user_session_data['user_agent']
        assert session.client_info == user_session_data['client_info']
        assert session.expires_at == user_session_data['expires_at']
        assert session.session_type == user_session_data['session_type']
        assert session.login_method == user_session_data['login_method']
        assert session.session_data == user_session_data['session_data']

    def test_user_session_defaults(self):
        """Test UserSession model default values."""
        session = UserSession(
            user_id=uuid4(),
            tenant_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )

        assert session.is_active is True
        assert session.client_info == {}
        assert session.session_data == {}
        assert session.session_type == 'web'
        assert session.terminated_at is None
        assert session.termination_reason is None
        assert session.device_id is None
        assert session.authentik_session_id is None
        assert isinstance(session.created_at, datetime)
        assert isinstance(session.last_activity, datetime)

    def test_user_session_repr(self, user_session_data):
        """Test UserSession string representation."""
        session = UserSession(**user_session_data)
        
        repr_str = repr(session)
        
        assert "UserSession" in repr_str
        assert str(user_session_data['user_id']) in repr_str
        assert str(user_session_data['tenant_id']) in repr_str
        assert "active=True" in repr_str

    def test_is_expired_false(self):
        """Test is_expired returns False for valid session."""
        session = UserSession(
            user_id=uuid4(),
            tenant_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )

        assert session.is_expired() is False

    def test_is_expired_true(self):
        """Test is_expired returns True for expired session."""
        session = UserSession(
            user_id=uuid4(),
            tenant_id=uuid4(),
            expires_at=datetime.utcnow() - timedelta(hours=1)
        )

        assert session.is_expired() is True

    def test_is_expired_boundary(self):
        """Test is_expired at exact expiration time."""
        # Set expiration to very recent past
        session = UserSession(
            user_id=uuid4(),
            tenant_id=uuid4(),
            expires_at=datetime.utcnow() - timedelta(microseconds=1)
        )

        assert session.is_expired() is True

    def test_is_valid_active_not_expired(self):
        """Test is_valid returns True for active, non-expired session."""
        session = UserSession(
            user_id=uuid4(),
            tenant_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(hours=1),
            is_active=True
        )

        assert session.is_valid() is True

    def test_is_valid_inactive(self):
        """Test is_valid returns False for inactive session."""
        session = UserSession(
            user_id=uuid4(),
            tenant_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(hours=1),
            is_active=False
        )

        assert session.is_valid() is False

    def test_is_valid_expired(self):
        """Test is_valid returns False for expired session."""
        session = UserSession(
            user_id=uuid4(),
            tenant_id=uuid4(),
            expires_at=datetime.utcnow() - timedelta(hours=1),
            is_active=True
        )

        assert session.is_valid() is False

    def test_is_valid_inactive_and_expired(self):
        """Test is_valid returns False for inactive and expired session."""
        session = UserSession(
            user_id=uuid4(),
            tenant_id=uuid4(),
            expires_at=datetime.utcnow() - timedelta(hours=1),
            is_active=False
        )

        assert session.is_valid() is False

    def test_update_activity(self):
        """Test update_activity updates last_activity timestamp."""
        session = UserSession(
            user_id=uuid4(),
            tenant_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )

        original_activity = session.last_activity
        
        # Wait a small amount to ensure time difference
        import time
        time.sleep(0.01)
        
        session.update_activity()

        assert session.last_activity > original_activity

    def test_terminate_default_reason(self):
        """Test terminate with default reason."""
        session = UserSession(
            user_id=uuid4(),
            tenant_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(hours=1),
            is_active=True
        )

        assert session.terminated_at is None
        assert session.termination_reason is None

        session.terminate()

        assert session.is_active is False
        assert isinstance(session.terminated_at, datetime)
        assert session.termination_reason == "logout"

    def test_terminate_custom_reason(self):
        """Test terminate with custom reason."""
        session = UserSession(
            user_id=uuid4(),
            tenant_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(hours=1),
            is_active=True
        )

        session.terminate("admin_revoked")

        assert session.is_active is False
        assert isinstance(session.terminated_at, datetime)
        assert session.termination_reason == "admin_revoked"

    def test_terminate_idempotent(self):
        """Test terminate is idempotent."""
        session = UserSession(
            user_id=uuid4(),
            tenant_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(hours=1),
            is_active=True
        )

        # First termination
        session.terminate("logout")
        first_terminated_at = session.terminated_at
        first_reason = session.termination_reason

        # Second termination
        session.terminate("expired")

        # Values should remain from first termination
        assert session.terminated_at == first_terminated_at
        assert session.termination_reason == "expired"  # Reason can be updated

    def test_session_with_minimal_data(self):
        """Test session creation with minimal required data."""
        session = UserSession(
            user_id=uuid4(),
            tenant_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )

        # Should work without errors
        assert session.user_id is not None
        assert session.tenant_id is not None
        assert session.expires_at is not None
        assert session.is_active is True

    def test_session_with_optional_null_values(self):
        """Test session with explicitly null optional values."""
        session = UserSession(
            user_id=uuid4(),
            tenant_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(hours=24),
            device_id=None,
            authentik_session_id=None,
            ip_address_hash=None,
            user_agent=None,
            terminated_at=None,
            termination_reason=None
        )

        assert session.device_id is None
        assert session.authentik_session_id is None
        assert session.ip_address_hash is None
        assert session.user_agent is None
        assert session.terminated_at is None
        assert session.termination_reason is None


class TestSessionActivity:
    """Test SessionActivity model functionality."""

    @pytest.fixture
    def session_activity_data(self):
        """Base data for creating session activities."""
        return {
            'session_id': uuid4(),
            'activity_type': 'api_call',
            'activity_category': 'data',
            'duration_ms': 150,
            'endpoint': '/api/v1/conversations',
            'http_method': 'GET',
            'status_code': 200,
            'details': {'query_params': {'limit': 10}, 'response_size': '2.5KB'},
            'resource_type': 'conversation',
            'resource_id': uuid4(),
            'ip_address_hash': 'abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234',
            'user_agent_hash': 'efgh5678901234efgh5678901234efgh5678901234efgh5678901234efgh5678',
            'success': True,
            'error_code': None,
            'error_message': None
        }

    def test_session_activity_creation(self, session_activity_data):
        """Test SessionActivity model creation."""
        activity = SessionActivity(**session_activity_data)

        assert activity.session_id == session_activity_data['session_id']
        assert activity.activity_type == session_activity_data['activity_type']
        assert activity.activity_category == session_activity_data['activity_category']
        assert activity.duration_ms == session_activity_data['duration_ms']
        assert activity.endpoint == session_activity_data['endpoint']
        assert activity.http_method == session_activity_data['http_method']
        assert activity.status_code == session_activity_data['status_code']
        assert activity.details == session_activity_data['details']
        assert activity.resource_type == session_activity_data['resource_type']
        assert activity.resource_id == session_activity_data['resource_id']
        assert activity.ip_address_hash == session_activity_data['ip_address_hash']
        assert activity.user_agent_hash == session_activity_data['user_agent_hash']
        assert activity.success == session_activity_data['success']
        assert activity.error_code == session_activity_data['error_code']
        assert activity.error_message == session_activity_data['error_message']

    def test_session_activity_defaults(self):
        """Test SessionActivity model default values."""
        activity = SessionActivity(
            session_id=uuid4(),
            activity_type='login'
        )

        assert activity.details == {}
        assert isinstance(activity.timestamp, datetime)
        assert activity.activity_category is None
        assert activity.duration_ms is None
        assert activity.endpoint is None
        assert activity.http_method is None
        assert activity.status_code is None

    def test_session_activity_repr(self, session_activity_data):
        """Test SessionActivity string representation."""
        activity = SessionActivity(**session_activity_data)
        
        repr_str = repr(activity)
        
        assert "SessionActivity" in repr_str
        assert str(session_activity_data['session_id']) in repr_str
        assert session_activity_data['activity_type'] in repr_str
        assert "timestamp=" in repr_str

    def test_session_activity_with_error(self):
        """Test SessionActivity with error information."""
        activity = SessionActivity(
            session_id=uuid4(),
            activity_type='api_call',
            endpoint='/api/v1/protected',
            http_method='POST',
            status_code=403,
            success=False,
            error_code='PERMISSION_DENIED',
            error_message='User lacks required permissions'
        )

        assert activity.success is False
        assert activity.error_code == 'PERMISSION_DENIED'
        assert activity.error_message == 'User lacks required permissions'
        assert activity.status_code == 403

    def test_session_activity_minimal(self):
        """Test SessionActivity with minimal required data."""
        activity = SessionActivity(
            session_id=uuid4(),
            activity_type='logout'
        )

        assert activity.session_id is not None
        assert activity.activity_type == 'logout'
        assert isinstance(activity.timestamp, datetime)

    def test_session_activity_with_complex_details(self):
        """Test SessionActivity with complex details JSON."""
        complex_details = {
            'user_action': 'file_upload',
            'file_info': {
                'name': 'document.pdf',
                'size': 1024000,
                'type': 'application/pdf'
            },
            'processing_steps': ['validation', 'virus_scan', 'ocr'],
            'metadata': {
                'pages': 5,
                'language': 'en',
                'confidence': 0.95
            }
        }

        activity = SessionActivity(
            session_id=uuid4(),
            activity_type='file_upload',
            activity_category='data',
            details=complex_details
        )

        assert activity.details == complex_details
        assert activity.details['file_info']['name'] == 'document.pdf'
        assert activity.details['metadata']['confidence'] == 0.95

    def test_session_activity_different_types(self):
        """Test SessionActivity with different activity types."""
        activity_types = [
            'login', 'logout', 'api_call', 'tenant_switch', 
            'password_change', 'mfa_challenge', 'file_access'
        ]

        for activity_type in activity_types:
            activity = SessionActivity(
                session_id=uuid4(),
                activity_type=activity_type
            )
            assert activity.activity_type == activity_type

    def test_session_activity_categories(self):
        """Test SessionActivity with different categories."""
        categories = ['auth', 'data', 'admin', 'security', 'audit']

        for category in categories:
            activity = SessionActivity(
                session_id=uuid4(),
                activity_type='test_action',
                activity_category=category
            )
            assert activity.activity_category == category


class TestSessionSecurityEvent:
    """Test SessionSecurityEvent model functionality."""

    @pytest.fixture
    def security_event_data(self):
        """Base data for creating security events."""
        return {
            'session_id': uuid4(),
            'user_id': uuid4(),
            'event_type': 'suspicious_login',
            'severity': 'high',
            'ip_address_hash': 'abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234',
            'user_agent': 'Mozilla/5.0 Suspicious Browser',
            'location_info': {'country': 'US', 'region': 'CA', 'city': 'Unknown'},
            'description': 'Login attempt from unusual location',
            'details': {
                'login_attempts': 3,
                'time_window': '5_minutes',
                'previous_locations': ['New York', 'California'],
                'current_location': 'Foreign Country'
            },
            'action_taken': 'require_mfa',
            'resolved': False,
            'resolved_at': None,
            'resolved_by': None
        }

    def test_security_event_creation(self, security_event_data):
        """Test SessionSecurityEvent model creation."""
        event = SessionSecurityEvent(**security_event_data)

        assert event.session_id == security_event_data['session_id']
        assert event.user_id == security_event_data['user_id']
        assert event.event_type == security_event_data['event_type']
        assert event.severity == security_event_data['severity']
        assert event.ip_address_hash == security_event_data['ip_address_hash']
        assert event.user_agent == security_event_data['user_agent']
        assert event.location_info == security_event_data['location_info']
        assert event.description == security_event_data['description']
        assert event.details == security_event_data['details']
        assert event.action_taken == security_event_data['action_taken']
        assert event.resolved == security_event_data['resolved']
        assert event.resolved_at == security_event_data['resolved_at']
        assert event.resolved_by == security_event_data['resolved_by']

    def test_security_event_defaults(self):
        """Test SessionSecurityEvent model default values."""
        event = SessionSecurityEvent(
            user_id=uuid4(),
            event_type='test_event',
            description='Test security event'
        )

        assert event.severity == 'medium'
        assert event.details == {}
        assert event.resolved is False
        assert event.resolved_at is None
        assert event.resolved_by is None
        assert isinstance(event.timestamp, datetime)

    def test_security_event_repr(self, security_event_data):
        """Test SessionSecurityEvent string representation."""
        event = SessionSecurityEvent(**security_event_data)
        
        repr_str = repr(event)
        
        assert "SessionSecurityEvent" in repr_str
        assert str(security_event_data['user_id']) in repr_str
        assert security_event_data['event_type'] in repr_str
        assert security_event_data['severity'] in repr_str

    def test_security_event_without_session(self):
        """Test SessionSecurityEvent without associated session."""
        event = SessionSecurityEvent(
            session_id=None,  # No session associated
            user_id=uuid4(),
            event_type='failed_login',
            severity='medium',
            description='Failed login attempt before session creation'
        )

        assert event.session_id is None
        assert event.user_id is not None
        assert event.event_type == 'failed_login'

    def test_security_event_severity_levels(self):
        """Test SessionSecurityEvent with different severity levels."""
        severity_levels = ['low', 'medium', 'high', 'critical']

        for severity in severity_levels:
            event = SessionSecurityEvent(
                user_id=uuid4(),
                event_type='test_event',
                severity=severity,
                description='Test event'
            )
            assert event.severity == severity

    def test_security_event_different_types(self):
        """Test SessionSecurityEvent with different event types."""
        event_types = [
            'suspicious_login', 'concurrent_sessions', 'location_change',
            'device_change', 'brute_force_attempt', 'privilege_escalation',
            'data_exfiltration', 'session_hijacking'
        ]

        for event_type in event_types:
            event = SessionSecurityEvent(
                user_id=uuid4(),
                event_type=event_type,
                description=f'Test {event_type} event'
            )
            assert event.event_type == event_type

    def test_security_event_resolution(self):
        """Test SessionSecurityEvent resolution workflow."""
        event = SessionSecurityEvent(
            user_id=uuid4(),
            event_type='suspicious_activity',
            severity='high',
            description='Suspicious user activity detected'
        )

        # Initially unresolved
        assert event.resolved is False
        assert event.resolved_at is None
        assert event.resolved_by is None

        # Resolve the event
        resolver_id = uuid4()
        resolution_time = datetime.utcnow()
        
        event.resolved = True
        event.resolved_at = resolution_time
        event.resolved_by = resolver_id

        assert event.resolved is True
        assert event.resolved_at == resolution_time
        assert event.resolved_by == resolver_id

    def test_security_event_with_complex_details(self):
        """Test SessionSecurityEvent with complex details."""
        complex_details = {
            'threat_indicators': {
                'ip_reputation': 'malicious',
                'user_agent_anomaly': True,
                'login_pattern_deviation': 0.85
            },
            'risk_score': 9.2,
            'detection_rules': ['rule_001', 'rule_045', 'rule_089'],
            'correlation_data': {
                'similar_events': 3,
                'time_window': '1_hour',
                'affected_users': 1
            },
            'mitigation_steps': [
                'block_ip',
                'require_password_reset',
                'notify_security_team'
            ]
        }

        event = SessionSecurityEvent(
            user_id=uuid4(),
            event_type='advanced_threat',
            severity='critical',
            description='Advanced persistent threat detected',
            details=complex_details
        )

        assert event.details == complex_details
        assert event.details['risk_score'] == 9.2
        assert 'block_ip' in event.details['mitigation_steps']

    def test_security_event_with_location_info(self):
        """Test SessionSecurityEvent with location information."""
        location_info = {
            'country': 'United States',
            'country_code': 'US',
            'region': 'California',
            'city': 'San Francisco',
            'latitude': 37.7749,
            'longitude': -122.4194,
            'isp': 'Example ISP',
            'timezone': 'America/Los_Angeles'
        }

        event = SessionSecurityEvent(
            user_id=uuid4(),
            event_type='location_anomaly',
            description='Login from unusual location',
            location_info=location_info
        )

        assert event.location_info == location_info
        assert event.location_info['country'] == 'United States'
        assert event.location_info['latitude'] == 37.7749

    def test_security_event_action_taken_options(self):
        """Test SessionSecurityEvent with different actions taken."""
        actions = [
            'block', 'alert', 'require_mfa', 'force_logout',
            'lock_account', 'notify_admin', 'quarantine_session'
        ]

        for action in actions:
            event = SessionSecurityEvent(
                user_id=uuid4(),
                event_type='security_violation',
                description='Security violation detected',
                action_taken=action
            )
            assert event.action_taken == action


class TestSessionModelRelationships:
    """Test relationships between session models."""

    def test_session_activity_relationship_setup(self):
        """Test SessionActivity relationship configuration."""
        # This tests the model setup, not database operations
        activity = SessionActivity(
            session_id=uuid4(),
            activity_type='test'
        )

        # Test that relationship attributes exist
        assert hasattr(activity, 'session')
        # The actual relationship would be tested in integration tests

    def test_security_event_relationship_setup(self):
        """Test SessionSecurityEvent relationship configuration."""
        event = SessionSecurityEvent(
            user_id=uuid4(),
            event_type='test',
            description='test'
        )

        # Test that relationship attributes exist
        assert hasattr(event, 'session')
        assert hasattr(event, 'user')
        assert hasattr(event, 'resolver')

    def test_user_session_relationship_setup(self):
        """Test UserSession relationship configuration."""
        session = UserSession(
            user_id=uuid4(),
            tenant_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )

        # Test that relationship attributes exist
        assert hasattr(session, 'user')
        assert hasattr(session, 'tenant')
        assert hasattr(session, 'device')
        assert hasattr(session, 'activities')


class TestSessionModelEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_session_with_very_long_user_agent(self):
        """Test session with extremely long user agent string."""
        very_long_user_agent = "A" * 2000  # Very long user agent
        
        session = UserSession(
            user_id=uuid4(),
            tenant_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(hours=24),
            user_agent=very_long_user_agent
        )

        assert session.user_agent == very_long_user_agent

    def test_session_with_large_json_data(self):
        """Test session with large JSON data."""
        large_data = {f"key_{i}": f"value_{i}" * 100 for i in range(100)}
        
        session = UserSession(
            user_id=uuid4(),
            tenant_id=uuid4(),
            expires_at=datetime.utcnow() + timedelta(hours=24),
            session_data=large_data
        )

        assert len(session.session_data) == 100
        assert session.session_data["key_0"] == "value_0" * 100

    def test_activity_with_zero_duration(self):
        """Test activity with zero duration."""
        activity = SessionActivity(
            session_id=uuid4(),
            activity_type='instant_action',
            duration_ms=0
        )

        assert activity.duration_ms == 0

    def test_activity_with_negative_status_code(self):
        """Test activity with unusual status code."""
        activity = SessionActivity(
            session_id=uuid4(),
            activity_type='network_error',
            status_code=-1  # Unusual but possible
        )

        assert activity.status_code == -1

    def test_security_event_with_empty_description(self):
        """Test security event with minimal description."""
        event = SessionSecurityEvent(
            user_id=uuid4(),
            event_type='test',
            description=''  # Empty but not null
        )

        assert event.description == ''

    def test_session_expiration_in_far_future(self):
        """Test session with expiration very far in the future."""
        far_future = datetime.utcnow() + timedelta(days=365*10)  # 10 years
        
        session = UserSession(
            user_id=uuid4(),
            tenant_id=uuid4(),
            expires_at=far_future
        )

        assert session.expires_at == far_future
        assert session.is_expired() is False

    def test_session_expiration_in_far_past(self):
        """Test session with expiration very far in the past."""
        far_past = datetime.utcnow() - timedelta(days=365*10)  # 10 years ago
        
        session = UserSession(
            user_id=uuid4(),
            tenant_id=uuid4(),
            expires_at=far_past
        )

        assert session.expires_at == far_past
        assert session.is_expired() is True