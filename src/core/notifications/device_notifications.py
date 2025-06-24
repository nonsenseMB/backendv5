"""Device security notification system."""
import asyncio
from datetime import datetime
from typing import Any

from src.core.config import settings
from src.core.logging import get_logger
from src.core.logging.audit import AuditEventType, AuditSeverity, log_audit_event

logger = get_logger(__name__)


class DeviceNotificationManager:
    """Manages security notifications for device operations."""

    def __init__(self):
        """Initialize notification manager."""
        self.email_enabled = getattr(settings, "DEVICE_NOTIFICATIONS_EMAIL", True)
        self.sms_enabled = getattr(settings, "DEVICE_NOTIFICATIONS_SMS", False)
        self.slack_enabled = getattr(settings, "DEVICE_NOTIFICATIONS_SLACK", False)

        # Notification preferences
        self.notify_on_new_device = True
        self.notify_on_device_removal = True
        self.notify_on_suspicious_activity = True
        self.notify_on_trust_changes = False  # Only for significant changes

    async def send_new_device_notification(
        self,
        user_email: str,
        device_name: str,
        device_type: str,
        ip_address: str | None = None,
        location: str | None = None,
        user_agent: str | None = None
    ) -> bool:
        """
        Send notification for new device registration.
        
        Args:
            user_email: User's email address
            device_name: Name of the registered device
            device_type: Type of device (webauthn, certificate)
            ip_address: IP address of registration
            location: Geographic location (if available)
            user_agent: User agent string
            
        Returns:
            Success status
        """
        try:
            notification_data = {
                "type": "new_device",
                "user_email": user_email,
                "device_name": device_name,
                "device_type": device_type,
                "timestamp": datetime.utcnow().isoformat(),
                "ip_address": ip_address,
                "location": location,
                "user_agent": user_agent
            }

            # Create email content
            subject = f"New Device Registered - {device_name}"
            message = self._create_new_device_message(notification_data)

            # Send notifications
            success = await self._send_notification(
                email=user_email,
                subject=subject,
                message=message,
                notification_type="security_alert",
                data=notification_data
            )

            logger.info(
                "New device notification sent",
                user_email=user_email,
                device_name=device_name,
                success=success
            )

            return success

        except Exception as e:
            logger.error(
                "Failed to send new device notification",
                user_email=user_email,
                device_name=device_name,
                error=str(e),
                exc_info=True
            )
            return False

    async def send_device_removal_notification(
        self,
        user_email: str,
        device_name: str,
        device_type: str,
        removed_by_current_device: bool = False,
        ip_address: str | None = None
    ) -> bool:
        """
        Send notification for device removal.
        
        Args:
            user_email: User's email address
            device_name: Name of the removed device
            device_type: Type of device
            removed_by_current_device: Whether removed by the current device
            ip_address: IP address of removal request
            
        Returns:
            Success status
        """
        try:
            notification_data = {
                "type": "device_removal",
                "user_email": user_email,
                "device_name": device_name,
                "device_type": device_type,
                "timestamp": datetime.utcnow().isoformat(),
                "removed_by_current_device": removed_by_current_device,
                "ip_address": ip_address
            }

            subject = f"Device Removed - {device_name}"
            message = self._create_device_removal_message(notification_data)

            success = await self._send_notification(
                email=user_email,
                subject=subject,
                message=message,
                notification_type="security_alert",
                data=notification_data
            )

            logger.info(
                "Device removal notification sent",
                user_email=user_email,
                device_name=device_name,
                success=success
            )

            return success

        except Exception as e:
            logger.error(
                "Failed to send device removal notification",
                user_email=user_email,
                device_name=device_name,
                error=str(e),
                exc_info=True
            )
            return False

    async def send_suspicious_activity_notification(
        self,
        user_email: str,
        device_name: str,
        activity_type: str,
        activity_details: dict[str, Any],
        severity: str = "medium"
    ) -> bool:
        """
        Send notification for suspicious device activity.
        
        Args:
            user_email: User's email address
            device_name: Name of the device
            activity_type: Type of suspicious activity
            activity_details: Details about the activity
            severity: Severity level (low, medium, high)
            
        Returns:
            Success status
        """
        try:
            notification_data = {
                "type": "suspicious_activity",
                "user_email": user_email,
                "device_name": device_name,
                "activity_type": activity_type,
                "activity_details": activity_details,
                "severity": severity,
                "timestamp": datetime.utcnow().isoformat()
            }

            subject = f"⚠️ Suspicious Activity Detected - {device_name}"
            message = self._create_suspicious_activity_message(notification_data)

            success = await self._send_notification(
                email=user_email,
                subject=subject,
                message=message,
                notification_type="security_alert",
                data=notification_data,
                priority="high" if severity == "high" else "normal"
            )

            # Also log as audit event
            log_audit_event(
                event_type=AuditEventType.SECURITY_ALERT,
                user_id=None,  # Will be filled by audit system
                resource=f"device:{device_name}",
                severity=AuditSeverity.HIGH if severity == "high" else AuditSeverity.MEDIUM,
                details={
                    "activity_type": activity_type,
                    "activity_details": activity_details,
                    "notification_sent": success
                }
            )

            logger.warning(
                "Suspicious activity notification sent",
                user_email=user_email,
                device_name=device_name,
                activity_type=activity_type,
                severity=severity,
                success=success
            )

            return success

        except Exception as e:
            logger.error(
                "Failed to send suspicious activity notification",
                user_email=user_email,
                device_name=device_name,
                error=str(e),
                exc_info=True
            )
            return False

    async def send_trust_level_change_notification(
        self,
        user_email: str,
        device_name: str,
        old_trust_level: str,
        new_trust_level: str,
        trust_score: int,
        change_reason: str
    ) -> bool:
        """
        Send notification for significant trust level changes.
        
        Args:
            user_email: User's email address
            device_name: Name of the device
            old_trust_level: Previous trust level
            new_trust_level: New trust level
            trust_score: Current trust score
            change_reason: Reason for the change
            
        Returns:
            Success status
        """
        try:
            # Only notify for significant changes (to high/low trust)
            significant_change = (
                (old_trust_level != "low" and new_trust_level == "low") or
                (old_trust_level != "high" and new_trust_level == "high")
            )

            if not significant_change:
                return True  # Skip notification

            notification_data = {
                "type": "trust_level_change",
                "user_email": user_email,
                "device_name": device_name,
                "old_trust_level": old_trust_level,
                "new_trust_level": new_trust_level,
                "trust_score": trust_score,
                "change_reason": change_reason,
                "timestamp": datetime.utcnow().isoformat()
            }

            subject = f"Device Trust Level Changed - {device_name}"
            message = self._create_trust_change_message(notification_data)

            success = await self._send_notification(
                email=user_email,
                subject=subject,
                message=message,
                notification_type="security_info",
                data=notification_data
            )

            logger.info(
                "Trust level change notification sent",
                user_email=user_email,
                device_name=device_name,
                old_trust_level=old_trust_level,
                new_trust_level=new_trust_level,
                success=success
            )

            return success

        except Exception as e:
            logger.error(
                "Failed to send trust level change notification",
                user_email=user_email,
                device_name=device_name,
                error=str(e),
                exc_info=True
            )
            return False

    async def send_device_update_notification(
        self,
        user_email: str,
        device_name: str,
        change_type: str,
        old_value: str,
        new_value: str,
        ip_address: str | None = None
    ) -> bool:
        """
        Send notification for device updates.
        
        Args:
            user_email: User's email address
            device_name: Name of the device
            change_type: Type of change made
            old_value: Previous value
            new_value: New value
            ip_address: IP address of the change
            
        Returns:
            Success status
        """
        try:
            notification_data = {
                "type": "device_update",
                "user_email": user_email,
                "device_name": device_name,
                "change_type": change_type,
                "old_value": old_value,
                "new_value": new_value,
                "timestamp": datetime.utcnow().isoformat(),
                "ip_address": ip_address
            }

            subject = f"Device Updated - {device_name}"
            message = self._create_device_update_message(notification_data)

            success = await self._send_notification(
                email=user_email,
                subject=subject,
                message=message,
                notification_type="security_info",
                data=notification_data
            )

            logger.info(
                "Device update notification sent",
                user_email=user_email,
                device_name=device_name,
                change_type=change_type,
                success=success
            )

            return success

        except Exception as e:
            logger.error(
                "Failed to send device update notification",
                user_email=user_email,
                device_name=device_name,
                error=str(e),
                exc_info=True
            )
            return False

    def _create_new_device_message(self, data: dict[str, Any]) -> str:
        """Create email message for new device registration."""
        message = f"""
A new device has been registered to your account:

Device Name: {data['device_name']}
Device Type: {data['device_type'].upper()}
Registration Time: {data['timestamp']}
"""

        if data.get('ip_address'):
            message += f"IP Address: {data['ip_address']}\n"

        if data.get('location'):
            message += f"Location: {data['location']}\n"

        if data.get('user_agent'):
            message += f"Browser: {data['user_agent']}\n"

        message += """
If this was not you, please immediately:
1. Sign in to your account
2. Review your registered devices
3. Remove any unrecognized devices
4. Contact support if you need assistance

For your security, we recommend using strong, unique passwords and enabling two-factor authentication.
"""

        return message

    def _create_device_removal_message(self, data: dict[str, Any]) -> str:
        """Create email message for device removal."""
        action = "from your current device" if data['removed_by_current_device'] else "remotely"

        message = f"""
A device has been removed from your account:

Device Name: {data['device_name']}
Device Type: {data['device_type'].upper()}
Removal Time: {data['timestamp']}
Removed: {action}
"""

        if data.get('ip_address'):
            message += f"IP Address: {data['ip_address']}\n"

        message += """
If this was not you, please immediately:
1. Sign in to your account
2. Check for any remaining unrecognized devices
3. Change your password
4. Contact support

This action was logged for security purposes.
"""

        return message

    def _create_suspicious_activity_message(self, data: dict[str, Any]) -> str:
        """Create email message for suspicious activity."""
        message = f"""
⚠️ SECURITY ALERT: Suspicious activity detected on your device:

Device Name: {data['device_name']}
Activity Type: {data['activity_type']}
Severity: {data['severity'].upper()}
Detection Time: {data['timestamp']}

Activity Details:
"""

        for key, value in data['activity_details'].items():
            message += f"- {key.replace('_', ' ').title()}: {value}\n"

        message += """
Recommended Actions:
1. Review your recent account activity
2. Check for unrecognized devices
3. Update your password if necessary
4. Contact support if you believe your account is compromised

This activity has been logged and is being monitored.
"""

        return message

    def _create_trust_change_message(self, data: dict[str, Any]) -> str:
        """Create email message for trust level changes."""
        message = f"""
Your device trust level has changed:

Device Name: {data['device_name']}
Previous Trust Level: {data['old_trust_level'].title()}
New Trust Level: {data['new_trust_level'].title()}
Trust Score: {data['trust_score']}/100
Change Reason: {data['change_reason']}
Change Time: {data['timestamp']}

"""

        if data['new_trust_level'] == "high":
            message += """
✅ Your device now has HIGH trust level, which provides:
- Extended session timeouts
- Access to sensitive operations
- Fewer security prompts
"""
        elif data['new_trust_level'] == "low":
            message += """
⚠️ Your device now has LOW trust level, which means:
- Shorter session timeouts
- Limited access to sensitive operations
- Additional security verification required

To improve your device trust level, ensure regular usage and avoid suspicious activities.
"""

        return message

    def _create_device_update_message(self, data: dict[str, Any]) -> str:
        """Create email message for device updates."""
        change_type_display = data['change_type'].replace('_', ' ').title()

        message = f"""
A change has been made to one of your devices:

Device Name: {data['device_name']}
Change Type: {change_type_display}
Previous Value: {data['old_value']}
New Value: {data['new_value']}
Change Time: {data['timestamp']}
"""

        if data.get('ip_address'):
            message += f"IP Address: {data['ip_address']}\n"

        message += """
If this change was not made by you, please:
1. Sign in to your account immediately
2. Review all device settings
3. Remove any unrecognized devices
4. Change your password
5. Contact support if needed

All device changes are logged for security purposes.
"""

        return message

    async def _send_notification(
        self,
        email: str,
        subject: str,
        message: str,
        notification_type: str,
        data: dict[str, Any],
        priority: str = "normal"
    ) -> bool:
        """
        Send notification via configured channels.
        
        Args:
            email: Recipient email
            subject: Notification subject
            message: Notification message
            notification_type: Type of notification
            data: Notification data
            priority: Priority level
            
        Returns:
            Success status
        """
        success = True

        try:
            # Email notification
            if self.email_enabled:
                email_success = await self._send_email_notification(
                    email=email,
                    subject=subject,
                    message=message,
                    priority=priority
                )
                success = success and email_success

            # SMS notification (for high priority alerts)
            if self.sms_enabled and priority == "high":
                sms_success = await self._send_sms_notification(
                    email=email,  # Would need phone number lookup
                    message=f"{subject}: {notification_type}",
                    data=data
                )
                success = success and sms_success

            # Slack notification (for development/monitoring)
            if self.slack_enabled:
                slack_success = await self._send_slack_notification(
                    subject=subject,
                    message=message,
                    data=data,
                    priority=priority
                )
                # Don't fail on Slack errors

            return success

        except Exception as e:
            logger.error(
                "Failed to send notification",
                email=email,
                notification_type=notification_type,
                error=str(e),
                exc_info=True
            )
            return False

    async def _send_email_notification(
        self,
        email: str,
        subject: str,
        message: str,
        priority: str = "normal"
    ) -> bool:
        """Send email notification."""
        # In production, this would integrate with an email service
        # For now, we'll log the notification
        logger.info(
            "Email notification (simulated)",
            email=email,
            subject=subject,
            priority=priority,
            message_length=len(message)
        )

        # Simulate email sending
        await asyncio.sleep(0.1)
        return True

    async def _send_sms_notification(
        self,
        email: str,
        message: str,
        data: dict[str, Any]
    ) -> bool:
        """Send SMS notification."""
        # In production, this would integrate with an SMS service
        logger.info(
            "SMS notification (simulated)",
            email=email,
            message=message
        )

        await asyncio.sleep(0.1)
        return True

    async def _send_slack_notification(
        self,
        subject: str,
        message: str,
        data: dict[str, Any],
        priority: str = "normal"
    ) -> bool:
        """Send Slack notification."""
        # In production, this would integrate with Slack webhook
        logger.info(
            "Slack notification (simulated)",
            subject=subject,
            priority=priority,
            notification_type=data.get("type")
        )

        await asyncio.sleep(0.1)
        return True


# Global instance
device_notifications = DeviceNotificationManager()
