"""Unit tests for device notification system."""
import pytest
from datetime import datetime
from unittest.mock import Mock, patch, AsyncMock

from src.core.notifications.device_notifications import DeviceNotificationManager


class TestDeviceNotificationManager:
    """Test device notification functionality."""
    
    @pytest.fixture
    def notification_manager(self):
        """Create notification manager instance."""
        return DeviceNotificationManager()
    
    @pytest.mark.asyncio
    async def test_send_new_device_notification(self, notification_manager):
        """Test new device notification."""
        with patch.object(notification_manager, '_send_notification', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = True
            
            success = await notification_manager.send_new_device_notification(
                user_email="test@example.com",
                device_name="Test Device",
                device_type="webauthn",
                ip_address="192.168.1.1",
                location="San Francisco, CA"
            )
            
            assert success is True
            mock_send.assert_called_once()
            
            # Check call arguments
            call_args = mock_send.call_args
            assert call_args.kwargs["email"] == "test@example.com"
            assert "New Device Registered" in call_args.kwargs["subject"]
            assert "Test Device" in call_args.kwargs["message"]
    
    @pytest.mark.asyncio
    async def test_send_device_removal_notification(self, notification_manager):
        """Test device removal notification."""
        with patch.object(notification_manager, '_send_notification', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = True
            
            success = await notification_manager.send_device_removal_notification(
                user_email="test@example.com",
                device_name="Test Device",
                device_type="webauthn",
                removed_by_current_device=True,
                ip_address="192.168.1.1"
            )
            
            assert success is True
            mock_send.assert_called_once()
            
            call_args = mock_send.call_args
            assert "Device Removed" in call_args.kwargs["subject"]
            assert "from your current device" in call_args.kwargs["message"]
    
    @pytest.mark.asyncio
    async def test_send_suspicious_activity_notification(self, notification_manager):
        """Test suspicious activity notification."""
        with patch.object(notification_manager, '_send_notification', new_callable=AsyncMock) as mock_send:
            with patch('src.core.notifications.device_notifications.log_audit_event') as mock_audit:
                mock_send.return_value = True
                
                activity_details = {
                    "failed_attempts": 5,
                    "time_window": "10 minutes",
                    "source_ip": "192.168.1.100"
                }
                
                success = await notification_manager.send_suspicious_activity_notification(
                    user_email="test@example.com",
                    device_name="Test Device",
                    activity_type="multiple_failed_auth",
                    activity_details=activity_details,
                    severity="high"
                )
                
                assert success is True
                mock_send.assert_called_once()
                mock_audit.assert_called_once()
                
                call_args = mock_send.call_args
                assert "⚠️ Suspicious Activity Detected" in call_args.kwargs["subject"]
                assert call_args.kwargs["priority"] == "high"
    
    @pytest.mark.asyncio
    async def test_send_trust_level_change_notification(self, notification_manager):
        """Test trust level change notification."""
        with patch.object(notification_manager, '_send_notification', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = True
            
            # Test significant change (to low trust)
            success = await notification_manager.send_trust_level_change_notification(
                user_email="test@example.com",
                device_name="Test Device",
                old_trust_level="medium",
                new_trust_level="low",
                trust_score=30,
                change_reason="Multiple failed authentications"
            )
            
            assert success is True
            mock_send.assert_called_once()
            
            call_args = mock_send.call_args
            assert "Device Trust Level Changed" in call_args.kwargs["subject"]
            assert "LOW trust level" in call_args.kwargs["message"]
    
    @pytest.mark.asyncio
    async def test_trust_level_change_no_notification_for_minor_changes(self, notification_manager):
        """Test that minor trust level changes don't trigger notifications."""
        with patch.object(notification_manager, '_send_notification', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = True
            
            # Test insignificant change (medium to medium)
            success = await notification_manager.send_trust_level_change_notification(
                user_email="test@example.com",
                device_name="Test Device",
                old_trust_level="medium",
                new_trust_level="medium",
                trust_score=65,
                change_reason="Minor adjustment"
            )
            
            assert success is True
            mock_send.assert_not_called()  # Should skip notification
    
    def test_create_new_device_message(self, notification_manager):
        """Test new device message creation."""
        data = {
            "device_name": "iPhone 15",
            "device_type": "webauthn",
            "timestamp": "2024-01-20T10:30:00Z",
            "ip_address": "192.168.1.100",
            "location": "San Francisco, CA",
            "user_agent": "Mozilla/5.0..."
        }
        
        message = notification_manager._create_new_device_message(data)
        
        assert "iPhone 15" in message
        assert "WEBAUTHN" in message
        assert "192.168.1.100" in message
        assert "San Francisco, CA" in message
        assert "If this was not you" in message
    
    def test_create_suspicious_activity_message(self, notification_manager):
        """Test suspicious activity message creation."""
        data = {
            "device_name": "Test Device",
            "activity_type": "multiple_failed_auth",
            "severity": "high",
            "timestamp": "2024-01-20T10:30:00Z",
            "activity_details": {
                "failed_attempts": 5,
                "time_window": "10 minutes"
            }
        }
        
        message = notification_manager._create_suspicious_activity_message(data)
        
        assert "⚠️ SECURITY ALERT" in message
        assert "Test Device" in message
        assert "HIGH" in message
        assert "Failed Attempts: 5" in message
        assert "Time Window: 10 minutes" in message
    
    def test_create_trust_change_message_high_trust(self, notification_manager):
        """Test trust change message for high trust."""
        data = {
            "device_name": "Test Device",
            "old_trust_level": "medium",
            "new_trust_level": "high",
            "trust_score": 85,
            "change_reason": "Consistent usage",
            "timestamp": "2024-01-20T10:30:00Z"
        }
        
        message = notification_manager._create_trust_change_message(data)
        
        assert "Test Device" in message
        assert "Medium" in message
        assert "High" in message
        assert "85/100" in message
        assert "✅" in message
        assert "HIGH trust level" in message
    
    def test_create_trust_change_message_low_trust(self, notification_manager):
        """Test trust change message for low trust."""
        data = {
            "device_name": "Test Device",
            "old_trust_level": "medium",
            "new_trust_level": "low",
            "trust_score": 25,
            "change_reason": "Suspicious activity",
            "timestamp": "2024-01-20T10:30:00Z"
        }
        
        message = notification_manager._create_trust_change_message(data)
        
        assert "⚠️" in message
        assert "LOW trust level" in message
        assert "Shorter session timeouts" in message
        assert "improve your device trust level" in message
    
    @pytest.mark.asyncio
    async def test_send_notification_email_only(self, notification_manager):
        """Test sending notification with email only."""
        notification_manager.email_enabled = True
        notification_manager.sms_enabled = False
        notification_manager.slack_enabled = False
        
        with patch.object(notification_manager, '_send_email_notification', new_callable=AsyncMock) as mock_email:
            mock_email.return_value = True
            
            success = await notification_manager._send_notification(
                email="test@example.com",
                subject="Test Subject",
                message="Test message",
                notification_type="test",
                data={}
            )
            
            assert success is True
            mock_email.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_send_notification_high_priority_with_sms(self, notification_manager):
        """Test high priority notification triggers SMS."""
        notification_manager.email_enabled = True
        notification_manager.sms_enabled = True
        
        with patch.object(notification_manager, '_send_email_notification', new_callable=AsyncMock) as mock_email:
            with patch.object(notification_manager, '_send_sms_notification', new_callable=AsyncMock) as mock_sms:
                mock_email.return_value = True
                mock_sms.return_value = True
                
                success = await notification_manager._send_notification(
                    email="test@example.com",
                    subject="Test Subject",
                    message="Test message",
                    notification_type="test",
                    data={},
                    priority="high"
                )
                
                assert success is True
                mock_email.assert_called_once()
                mock_sms.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_send_email_notification(self, notification_manager):
        """Test email notification sending."""
        success = await notification_manager._send_email_notification(
            email="test@example.com",
            subject="Test Subject",
            message="Test message",
            priority="normal"
        )
        
        # Should succeed (simulated)
        assert success is True
    
    @pytest.mark.asyncio
    async def test_notification_error_handling(self, notification_manager):
        """Test notification error handling."""
        with patch.object(notification_manager, '_send_email_notification', new_callable=AsyncMock) as mock_email:
            mock_email.side_effect = Exception("Email service error")
            
            success = await notification_manager.send_new_device_notification(
                user_email="test@example.com",
                device_name="Test Device",
                device_type="webauthn"
            )
            
            # Should handle error gracefully
            assert success is False