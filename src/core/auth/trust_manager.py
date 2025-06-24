"""Enhanced device trust management system."""
from datetime import datetime
from typing import Any
from uuid import UUID

from src.core.auth.device_trust import (
    TRUSTED_AAGUIDS,
    calculate_trust_score,
    get_trust_level_name,
    is_high_trust_device,
    is_medium_trust_device,
)
from src.core.logging import get_logger
from src.core.logging.audit import AuditEventType, AuditSeverity, log_audit_event

logger = get_logger(__name__)


class DeviceTrustManager:
    """Manages device trust scoring, policies, and analytics."""

    # Trust decay configuration
    TRUST_DECAY_RATE = 1  # Points lost per week of inactivity
    MIN_TRUST_SCORE = 10  # Minimum trust score
    MAX_TRUST_SCORE = 100  # Maximum trust score

    # Trust thresholds for policies
    HIGH_TRUST_THRESHOLD = 80
    MEDIUM_TRUST_THRESHOLD = 50

    # Policy configuration
    POLICIES = {
        "high_trust": {
            "session_timeout_minutes": 480,  # 8 hours
            "max_session_duration_minutes": 10080,  # 7 days
            "require_mfa": False,
            "allow_sensitive_operations": True,
            "allow_api_key_generation": True,
            "max_concurrent_sessions": 5,
        },
        "medium_trust": {
            "session_timeout_minutes": 120,  # 2 hours
            "max_session_duration_minutes": 1440,  # 24 hours
            "require_mfa": True,
            "allow_sensitive_operations": False,
            "allow_api_key_generation": False,
            "max_concurrent_sessions": 3,
        },
        "low_trust": {
            "session_timeout_minutes": 30,  # 30 minutes
            "max_session_duration_minutes": 480,  # 8 hours
            "require_mfa": True,
            "allow_sensitive_operations": False,
            "allow_api_key_generation": False,
            "max_concurrent_sessions": 1,
        }
    }

    def __init__(self):
        """Initialize trust manager."""
        self.analytics_cache = {}

    def calculate_initial_trust_score(
        self,
        attestation_type: str | None = None,
        authenticator_attachment: str | None = None,
        aaguid: UUID | None = None,
        user_verification: bool = True,
        is_resident_key: bool = False,
        attestation_data: dict | None = None
    ) -> tuple[int, dict[str, Any]]:
        """
        Calculate initial trust score with detailed breakdown.
        
        Returns:
            Tuple of (trust_score, score_breakdown)
        """
        breakdown = {
            "base_score": 10,
            "attestation_bonus": 0,
            "authenticator_bonus": 0,
            "known_device_bonus": 0,
            "verification_bonus": 0,
            "resident_key_bonus": 0,
            "additional_factors": 0
        }

        # Use existing calculation
        base_score = calculate_trust_score(
            attestation_type=attestation_type,
            authenticator_attachment=authenticator_attachment,
            aaguid=aaguid,
            user_verification=user_verification,
            is_resident_key=is_resident_key
        )

        # Enhanced scoring with attestation data
        if attestation_data:
            # Check for enterprise attestation
            if attestation_data.get("is_enterprise"):
                breakdown["additional_factors"] += 10

            # Check for hardware backing
            if attestation_data.get("has_hardware_backing"):
                breakdown["additional_factors"] += 5

            # Check for secure element
            if attestation_data.get("has_secure_element"):
                breakdown["additional_factors"] += 5

        # Fill in breakdown
        if attestation_type:
            if attestation_type == "enterprise":
                breakdown["attestation_bonus"] = 40
            elif attestation_type == "direct":
                breakdown["attestation_bonus"] = 30
            elif attestation_type == "indirect":
                breakdown["attestation_bonus"] = 20
            elif attestation_type == "none":
                breakdown["attestation_bonus"] = 5

        if authenticator_attachment == "platform":
            breakdown["authenticator_bonus"] = 20
        elif authenticator_attachment == "cross-platform":
            breakdown["authenticator_bonus"] = 10

        if aaguid and str(aaguid).lower() in TRUSTED_AAGUIDS:
            breakdown["known_device_bonus"] = TRUSTED_AAGUIDS[str(aaguid).lower()]["trust_bonus"]

        if user_verification:
            breakdown["verification_bonus"] = 10

        if is_resident_key:
            breakdown["resident_key_bonus"] = 5

        # Calculate final score with additional factors
        final_score = min(base_score + breakdown["additional_factors"], self.MAX_TRUST_SCORE)

        logger.info(
            "Calculated initial trust score",
            final_score=final_score,
            breakdown=breakdown
        )

        return final_score, breakdown

    def calculate_trust_decay(
        self,
        current_score: int,
        last_used: datetime,
        current_time: datetime | None = None
    ) -> int:
        """
        Calculate trust score decay based on inactivity.
        
        Args:
            current_score: Current trust score
            last_used: Last time device was used
            current_time: Current time (for testing)
            
        Returns:
            Decayed trust score
        """
        if current_time is None:
            current_time = datetime.utcnow()

        # Calculate weeks of inactivity
        time_diff = current_time - last_used
        weeks_inactive = time_diff.days // 7

        # Apply decay
        decay = weeks_inactive * self.TRUST_DECAY_RATE
        new_score = max(current_score - decay, self.MIN_TRUST_SCORE)

        if decay > 0:
            logger.info(
                "Applied trust decay",
                original_score=current_score,
                new_score=new_score,
                weeks_inactive=weeks_inactive,
                decay_amount=decay
            )

        return new_score

    def adjust_trust_for_behavior(
        self,
        current_score: int,
        device_analytics: dict[str, Any]
    ) -> tuple[int, list[str]]:
        """
        Adjust trust score based on device behavior.
        
        Args:
            current_score: Current trust score
            device_analytics: Analytics data for the device
            
        Returns:
            Tuple of (adjusted_score, reasons)
        """
        adjusted_score = current_score
        reasons = []

        # Positive adjustments
        if device_analytics.get("successful_auth_streak", 0) >= 50:
            adjusted_score += 10
            reasons.append("Excellent authentication streak (+10)")
        elif device_analytics.get("successful_auth_streak", 0) >= 20:
            adjusted_score += 5
            reasons.append("Good authentication streak (+5)")

        # Regular usage bonus
        if device_analytics.get("days_active_last_month", 0) >= 20:
            adjusted_score += 5
            reasons.append("Regular daily usage (+5)")

        # Location consistency bonus
        if device_analytics.get("location_consistency", 0) >= 0.9:
            adjusted_score += 3
            reasons.append("Consistent location usage (+3)")

        # Negative adjustments
        if device_analytics.get("failed_auth_attempts", 0) > 5:
            adjusted_score -= 10
            reasons.append("Multiple failed authentications (-10)")

        if device_analytics.get("suspicious_activity_count", 0) > 0:
            adjusted_score -= 20
            reasons.append("Suspicious activity detected (-20)")

        # Time-based patterns
        if device_analytics.get("unusual_time_access", 0) > 3:
            adjusted_score -= 5
            reasons.append("Unusual access times (-5)")

        # Ensure within bounds
        final_score = max(self.MIN_TRUST_SCORE, min(adjusted_score, self.MAX_TRUST_SCORE))

        if final_score != current_score:
            logger.info(
                "Adjusted trust score for behavior",
                original_score=current_score,
                final_score=final_score,
                reasons=reasons
            )

        return final_score, reasons

    def get_device_policy(self, trust_score: int) -> dict[str, Any]:
        """
        Get security policy based on device trust score.
        
        Args:
            trust_score: Device trust score
            
        Returns:
            Policy dictionary
        """
        if is_high_trust_device(trust_score):
            policy = self.POLICIES["high_trust"].copy()
            policy["trust_level"] = "high"
        elif is_medium_trust_device(trust_score):
            policy = self.POLICIES["medium_trust"].copy()
            policy["trust_level"] = "medium"
        else:
            policy = self.POLICIES["low_trust"].copy()
            policy["trust_level"] = "low"

        policy["trust_score"] = trust_score
        policy["trust_level_name"] = get_trust_level_name(trust_score)

        # Apply additional restrictions for very low trust
        if trust_score < 30:
            policy["session_timeout_minutes"] = 15
            policy["require_continuous_verification"] = True

        return policy

    def should_trigger_trust_review(
        self,
        device_id: UUID,
        trust_score: int,
        last_review: datetime | None = None,
        analytics: dict | None = None
    ) -> tuple[bool, list[str]]:
        """
        Determine if device trust should be reviewed.
        
        Args:
            device_id: Device identifier
            trust_score: Current trust score
            last_review: Last review timestamp
            analytics: Device analytics
            
        Returns:
            Tuple of (should_review, reasons)
        """
        reasons = []

        # Time-based review
        if last_review:
            days_since_review = (datetime.utcnow() - last_review).days
            if days_since_review > 90:
                reasons.append("Quarterly review due")
            elif days_since_review > 30 and trust_score < 50:
                reasons.append("Monthly review for low trust device")
        else:
            reasons.append("No previous review")

        # Analytics-based triggers
        if analytics:
            if analytics.get("failed_auth_attempts", 0) > 3:
                reasons.append("Multiple failed authentication attempts")

            if analytics.get("location_changes", 0) > 5:
                reasons.append("Frequent location changes")

            if analytics.get("unusual_activity_score", 0) > 0.7:
                reasons.append("Unusual activity detected")

        # Trust score triggers
        if trust_score < 30:
            reasons.append("Very low trust score")

        should_review = len(reasons) > 0

        if should_review:
            logger.info(
                "Trust review triggered",
                device_id=str(device_id),
                trust_score=trust_score,
                reasons=reasons
            )

        return should_review, reasons

    def record_device_event(
        self,
        device_id: UUID,
        event_type: str,
        success: bool,
        metadata: dict | None = None
    ):
        """
        Record device event for analytics.
        
        Args:
            device_id: Device identifier
            event_type: Type of event
            success: Whether event was successful
            metadata: Additional event metadata
        """
        # Initialize device analytics if not exists
        if str(device_id) not in self.analytics_cache:
            self.analytics_cache[str(device_id)] = {
                "successful_auth_count": 0,
                "failed_auth_count": 0,
                "successful_auth_streak": 0,
                "last_auth_time": None,
                "location_history": [],
                "access_times": [],
                "suspicious_events": []
            }

        analytics = self.analytics_cache[str(device_id)]

        # Update based on event type
        if event_type == "authentication":
            if success:
                analytics["successful_auth_count"] += 1
                analytics["successful_auth_streak"] += 1
            else:
                analytics["failed_auth_count"] += 1
                analytics["successful_auth_streak"] = 0
            analytics["last_auth_time"] = datetime.utcnow()

        elif event_type == "location_change":
            if metadata and "location" in metadata:
                analytics["location_history"].append({
                    "location": metadata["location"],
                    "timestamp": datetime.utcnow()
                })

        elif event_type == "suspicious_activity":
            analytics["suspicious_events"].append({
                "type": metadata.get("activity_type", "unknown"),
                "timestamp": datetime.utcnow(),
                "details": metadata
            })

        # Log significant events
        if event_type == "suspicious_activity":
            log_audit_event(
                event_type=AuditEventType.SECURITY_ALERT,
                device_id=str(device_id),
                severity=AuditSeverity.HIGH,
                details={
                    "event_type": event_type,
                    "metadata": metadata
                }
            )

    def get_device_analytics(self, device_id: UUID) -> dict[str, Any]:
        """
        Get analytics for a device.
        
        Args:
            device_id: Device identifier
            
        Returns:
            Analytics dictionary
        """
        if str(device_id) not in self.analytics_cache:
            return {
                "successful_auth_count": 0,
                "failed_auth_count": 0,
                "successful_auth_streak": 0,
                "has_analytics": False
            }

        analytics = self.analytics_cache[str(device_id)].copy()
        analytics["has_analytics"] = True

        # Calculate derived metrics
        total_auth = analytics["successful_auth_count"] + analytics["failed_auth_count"]
        if total_auth > 0:
            analytics["success_rate"] = analytics["successful_auth_count"] / total_auth
        else:
            analytics["success_rate"] = 0

        # Location consistency
        if len(analytics.get("location_history", [])) > 1:
            locations = [loc["location"] for loc in analytics["location_history"]]
            most_common = max(set(locations), key=locations.count)
            analytics["location_consistency"] = locations.count(most_common) / len(locations)
        else:
            analytics["location_consistency"] = 1.0

        return analytics

    def generate_trust_report(
        self,
        device_id: UUID,
        trust_score: int,
        device_info: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Generate comprehensive trust report for a device.
        
        Args:
            device_id: Device identifier
            trust_score: Current trust score
            device_info: Device information
            
        Returns:
            Trust report dictionary
        """
        analytics = self.get_device_analytics(device_id)
        policy = self.get_device_policy(trust_score)

        report = {
            "device_id": str(device_id),
            "timestamp": datetime.utcnow().isoformat(),
            "trust_score": trust_score,
            "trust_level": policy["trust_level_name"],
            "device_info": device_info,
            "analytics": analytics,
            "applied_policy": policy,
            "recommendations": []
        }

        # Add recommendations
        if trust_score < 50:
            report["recommendations"].append(
                "Consider re-authenticating with stronger attestation"
            )

        if analytics.get("failed_auth_count", 0) > 3:
            report["recommendations"].append(
                "Review failed authentication attempts"
            )

        if analytics.get("location_consistency", 1.0) < 0.5:
            report["recommendations"].append(
                "Device is being used from multiple locations"
            )

        logger.info(
            "Generated trust report",
            device_id=str(device_id),
            trust_score=trust_score,
            trust_level=policy["trust_level_name"]
        )

        return report


# Global instance
trust_manager = DeviceTrustManager()
