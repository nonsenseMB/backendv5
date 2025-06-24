"""Device trust scoring and management."""
from typing import Optional
from uuid import UUID

from src.core.logging import get_logger

logger = get_logger(__name__)


# Known AAGUIDs for trusted authenticators
TRUSTED_AAGUIDS = {
    # Windows Hello
    "08987058-cadc-4b81-b6e1-30de50dcbe96": {"name": "Windows Hello", "trust_bonus": 20},
    "9ddd1817-af5a-4672-a2b9-3e3dd95000a9": {"name": "Windows Hello TPM", "trust_bonus": 30},
    
    # Apple Touch ID / Face ID
    "dd4ec289-e01d-41c9-bb89-70fa845d4bf2": {"name": "Apple Touch ID", "trust_bonus": 25},
    
    # YubiKey
    "ee882879-721c-4913-9775-3dfcce97072a": {"name": "YubiKey 5", "trust_bonus": 35},
    "fa2b99dc-9e39-4257-8f92-4a30d23c4118": {"name": "YubiKey 5 NFC", "trust_bonus": 35},
    
    # Google Titan
    "0bb43545-fd2c-4185-87dd-feb0b2916ace": {"name": "Google Titan", "trust_bonus": 30},
}


def calculate_trust_score(
    attestation_type: Optional[str] = None,
    authenticator_attachment: Optional[str] = None,
    aaguid: Optional[UUID] = None,
    user_verification: bool = True,
    is_resident_key: bool = False
) -> int:
    """
    Calculate device trust score based on various factors.
    
    Args:
        attestation_type: Type of attestation (none, indirect, direct, enterprise)
        authenticator_attachment: Attachment type (platform, cross-platform)
        aaguid: Authenticator AAGUID
        user_verification: Whether user verification was performed
        is_resident_key: Whether resident key/discoverable credential
        
    Returns:
        Trust score between 0-100
    """
    score = 0
    
    # Base score for successful registration
    score += 10
    
    # Attestation scoring
    if attestation_type:
        if attestation_type == "enterprise":
            score += 40  # Highest trust - enterprise attestation
        elif attestation_type == "direct":
            score += 30  # Direct attestation from authenticator
        elif attestation_type == "indirect":
            score += 20  # Indirect attestation
        elif attestation_type == "none":
            score += 5   # Self-attestation only
    
    # Authenticator attachment scoring
    if authenticator_attachment:
        if authenticator_attachment == "platform":
            score += 20  # Platform authenticators (TPM, Secure Enclave)
        elif authenticator_attachment == "cross-platform":
            score += 10  # External authenticators (USB, NFC)
    
    # Known authenticator bonus
    if aaguid:
        aaguid_str = str(aaguid).lower()
        if aaguid_str in TRUSTED_AAGUIDS:
            authenticator_info = TRUSTED_AAGUIDS[aaguid_str]
            score += authenticator_info["trust_bonus"]
            logger.debug(
                "Known authenticator detected",
                aaguid=aaguid_str,
                name=authenticator_info["name"]
            )
    
    # User verification bonus
    if user_verification:
        score += 10  # PIN, biometric, or other user verification
    
    # Resident key bonus
    if is_resident_key:
        score += 5  # Discoverable credentials are more secure
    
    # Cap at 100
    final_score = min(score, 100)
    
    logger.info(
        "Calculated device trust score",
        attestation_type=attestation_type,
        authenticator_attachment=authenticator_attachment,
        aaguid=str(aaguid) if aaguid else None,
        user_verification=user_verification,
        is_resident_key=is_resident_key,
        final_score=final_score
    )
    
    return final_score


def is_high_trust_device(trust_score: int) -> bool:
    """
    Check if device has high trust level.
    
    Args:
        trust_score: Device trust score
        
    Returns:
        True if high trust (80+)
    """
    return trust_score >= 80


def is_medium_trust_device(trust_score: int) -> bool:
    """
    Check if device has medium trust level.
    
    Args:
        trust_score: Device trust score
        
    Returns:
        True if medium trust (50-79)
    """
    return 50 <= trust_score < 80


def is_low_trust_device(trust_score: int) -> bool:
    """
    Check if device has low trust level.
    
    Args:
        trust_score: Device trust score
        
    Returns:
        True if low trust (<50)
    """
    return trust_score < 50


def get_trust_level_name(trust_score: int) -> str:
    """
    Get human-readable trust level name.
    
    Args:
        trust_score: Device trust score
        
    Returns:
        Trust level name
    """
    if is_high_trust_device(trust_score):
        return "High"
    elif is_medium_trust_device(trust_score):
        return "Medium"
    else:
        return "Low"


def should_require_additional_verification(trust_score: int) -> bool:
    """
    Determine if additional verification should be required.
    
    Args:
        trust_score: Device trust score
        
    Returns:
        True if additional verification needed
    """
    # Require additional verification for low trust devices
    return is_low_trust_device(trust_score)


def get_session_timeout_minutes(trust_score: int) -> int:
    """
    Get recommended session timeout based on trust score.
    
    Args:
        trust_score: Device trust score
        
    Returns:
        Session timeout in minutes
    """
    if is_high_trust_device(trust_score):
        return 480  # 8 hours for high trust
    elif is_medium_trust_device(trust_score):
        return 120  # 2 hours for medium trust
    else:
        return 30   # 30 minutes for low trust


def get_max_session_duration_minutes(trust_score: int) -> int:
    """
    Get maximum session duration based on trust score.
    
    Args:
        trust_score: Device trust score
        
    Returns:
        Maximum session duration in minutes
    """
    if is_high_trust_device(trust_score):
        return 10080  # 7 days for high trust
    elif is_medium_trust_device(trust_score):
        return 1440   # 24 hours for medium trust
    else:
        return 480    # 8 hours for low trust


def adjust_trust_score_for_usage(
    current_score: int,
    use_count: int,
    days_since_registration: int,
    successful_auth_streak: int = 0
) -> int:
    """
    Adjust trust score based on usage patterns.
    
    Args:
        current_score: Current trust score
        use_count: Number of times device has been used
        days_since_registration: Days since device was registered
        successful_auth_streak: Consecutive successful authentications
        
    Returns:
        Adjusted trust score
    """
    adjusted_score = current_score
    
    # Bonus for regular usage
    if use_count > 50 and days_since_registration > 30:
        adjusted_score += 10
    elif use_count > 20 and days_since_registration > 14:
        adjusted_score += 5
    
    # Bonus for successful auth streak
    if successful_auth_streak > 20:
        adjusted_score += 5
    elif successful_auth_streak > 10:
        adjusted_score += 3
    
    # Cap at 100
    final_score = min(adjusted_score, 100)
    
    if final_score != current_score:
        logger.info(
            "Adjusted device trust score",
            current_score=current_score,
            adjusted_score=final_score,
            use_count=use_count,
            days_since_registration=days_since_registration,
            successful_auth_streak=successful_auth_streak
        )
    
    return final_score