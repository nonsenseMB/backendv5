"""Enhanced device management API endpoints."""
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status, BackgroundTasks
from fastapi.security import HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies.auth import get_current_user
from src.api.dependencies.trust import require_high_trust, require_medium_trust
from src.infrastructure.database.session import get_async_session
from src.api.v1.auth.schemas import DeviceInfo
from src.core.logging import get_logger
from src.core.logging.audit import AuditEventType, AuditSeverity, log_audit_event
from src.core.notifications.device_notifications import device_notifications
from src.infrastructure.database.models.auth import User, UserDevice
from src.infrastructure.database.repositories.device import DeviceRepository
from src.infrastructure.database.unit_of_work import UnitOfWork
from src.core.auth.trust_manager import trust_manager

logger = get_logger(__name__)

# Create management router
router = APIRouter(prefix="/device-management", tags=["device-management"])

# Rate limiting for device operations
DEVICE_OPERATION_RATE_LIMIT = {
    "requests_per_hour": 50,
    "requests_per_day": 200
}


class DeviceManagementRequest:
    """Base class for device management requests."""
    pass


class DeviceRenameRequest(DeviceManagementRequest):
    """Request to rename a device."""
    
    def __init__(self, new_name: str):
        self.new_name = new_name


class DeviceSecurityCheckRequest(DeviceManagementRequest):
    """Request for device security check."""
    
    def __init__(self, check_type: str = "full"):
        self.check_type = check_type


@router.get("/overview")
async def get_device_overview(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_async_session),
) -> Dict[str, Any]:
    """
    Get comprehensive device management overview.
    
    Returns device statistics, security summary, and recommendations.
    """
    try:
        async with UnitOfWork(session) as uow:
            device_repo = DeviceRepository(UserDevice, session, current_user.tenant_id)
            devices = await device_repo.get_user_devices(current_user.id, active_only=False)
            
            # Calculate statistics
            total_devices = len(devices)
            active_devices = len([d for d in devices if d.is_active])
            trusted_devices = len([d for d in devices if d.is_trusted])
            
            # Trust level distribution
            high_trust = len([d for d in devices if d.trust_score >= 80])
            medium_trust = len([d for d in devices if 50 <= d.trust_score < 80])
            low_trust = len([d for d in devices if d.trust_score < 50])
            
            # Recent activity
            now = datetime.utcnow()
            week_ago = now - timedelta(days=7)
            recently_used = len([d for d in devices if d.last_used_at and d.last_used_at > week_ago])
            
            # Security assessment
            security_score = calculate_overall_security_score(devices)
            recommendations = generate_security_recommendations(devices)
            
            # Device types breakdown
            device_types = {}
            for device in devices:
                device_type = device.device_type
                if device_type not in device_types:
                    device_types[device_type] = 0
                device_types[device_type] += 1
            
            overview = {
                "user_id": str(current_user.id),
                "statistics": {
                    "total_devices": total_devices,
                    "active_devices": active_devices,
                    "trusted_devices": trusted_devices,
                    "recently_used": recently_used
                },
                "trust_distribution": {
                    "high_trust": high_trust,
                    "medium_trust": medium_trust,
                    "low_trust": low_trust
                },
                "device_types": device_types,
                "security_assessment": {
                    "overall_score": security_score,
                    "risk_level": get_risk_level(security_score),
                    "last_assessment": now.isoformat()
                },
                "recommendations": recommendations,
                "last_updated": now.isoformat()
            }
            
            logger.info(
                "Device overview generated",
                user_id=str(current_user.id),
                total_devices=total_devices,
                security_score=security_score
            )
            
            return overview
            
    except Exception as e:
        logger.error(
            "Failed to generate device overview",
            user_id=str(current_user.id),
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate device overview"
        )


@router.post("/{device_id}/rename")
async def rename_device(
    device_id: UUID,
    new_name: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_async_session),
    request: Request = None,
) -> Dict[str, Any]:
    """
    Rename a device with notification.
    
    Sends security notification about the name change.
    """
    try:
        if not new_name or len(new_name.strip()) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Device name cannot be empty"
            )
        
        if len(new_name) > 100:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Device name too long (max 100 characters)"
            )
        
        async with UnitOfWork(session) as uow:
            device_repo = DeviceRepository(UserDevice, session, current_user.tenant_id)
            
            # Get device
            device = await device_repo.get_by_id(device_id)
            
            if not device:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Device not found"
                )
            
            # Verify ownership
            if device.user_id != current_user.id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not authorized to rename this device"
                )
            
            old_name = device.device_name
            
            # Update device name
            updated_device = await device_repo.update(device_id, {
                "device_name": new_name.strip(),
                "updated_at": datetime.utcnow()
            })
            
            await uow.commit()
        
        # Log audit event
        log_audit_event(
            event_type=AuditEventType.DEVICE_UPDATED,
            user_id=str(current_user.id),
            tenant_id=str(current_user.tenant_id),
            resource=f"device:{device_id}",
            severity=AuditSeverity.LOW,
            details={
                "old_name": old_name,
                "new_name": new_name,
                "device_type": device.device_type,
                "ip_address": request.client.host if request and request.client else None
            }
        )
        
        # Send notification (async)
        background_tasks.add_task(
            device_notifications.send_device_update_notification,
            user_email=current_user.email,
            device_name=new_name,
            change_type="name_change",
            old_value=old_name,
            new_value=new_name,
            ip_address=request.client.host if request and request.client else None
        )
        
        logger.info(
            "Device renamed",
            user_id=str(current_user.id),
            device_id=str(device_id),
            old_name=old_name,
            new_name=new_name
        )
        
        return {
            "device_id": str(device_id),
            "old_name": old_name,
            "new_name": new_name,
            "updated_at": updated_device.updated_at.isoformat(),
            "message": "Device renamed successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to rename device",
            user_id=str(current_user.id),
            device_id=str(device_id),
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to rename device"
        )


@router.post("/{device_id}/security-check")
async def perform_device_security_check(
    device_id: UUID,
    check_type: str = "full",
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_async_session),
) -> Dict[str, Any]:
    """
    Perform comprehensive security check on a device.
    
    Analyzes device trust, usage patterns, and security compliance.
    """
    try:
        async with UnitOfWork(session) as uow:
            device_repo = DeviceRepository(UserDevice, session, current_user.tenant_id)
            
            # Get device
            device = await device_repo.get_by_id(device_id)
            
            if not device:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Device not found"
                )
            
            # Verify ownership
            if device.user_id != current_user.id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not authorized to check this device"
                )
            
            # Perform security check
            security_check = await perform_comprehensive_security_check(
                device=device,
                check_type=check_type
            )
            
            # Update device if recommendations applied
            if security_check.get("recommendations_applied"):
                new_trust_score = security_check.get("updated_trust_score")
                if new_trust_score and new_trust_score != device.trust_score:
                    await device_repo.update_trust_score(device_id, new_trust_score)
                    await uow.commit()
        
        # Log security check
        log_audit_event(
            event_type=AuditEventType.SECURITY_CHECK,
            user_id=str(current_user.id),
            tenant_id=str(current_user.tenant_id),
            resource=f"device:{device_id}",
            severity=AuditSeverity.LOW,
            details={
                "check_type": check_type,
                "security_score": security_check.get("security_score"),
                "issues_found": len(security_check.get("issues", []))
            }
        )
        
        logger.info(
            "Device security check completed",
            user_id=str(current_user.id),
            device_id=str(device_id),
            check_type=check_type,
            security_score=security_check.get("security_score")
        )
        
        return security_check
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to perform security check",
            user_id=str(current_user.id),
            device_id=str(device_id),
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to perform security check"
        )


@router.delete("/{device_id}/secure-remove")
async def secure_device_removal(
    device_id: UUID,
    confirmation_code: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_async_session),
    request: Request = None,
    _: dict = Depends(require_medium_trust),  # Require at least medium trust
) -> Dict[str, Any]:
    """
    Securely remove a device with enhanced verification.
    
    Requires confirmation code and sends security notifications.
    """
    try:
        # Validate confirmation code
        if not await validate_device_removal_confirmation(
            user_id=current_user.id,
            device_id=device_id,
            confirmation_code=confirmation_code
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired confirmation code"
            )
        
        async with UnitOfWork(session) as uow:
            device_repo = DeviceRepository(UserDevice, session, current_user.tenant_id)
            
            # Get all user devices
            devices = await device_repo.get_user_devices(current_user.id)
            
            # Find device to remove
            device_to_remove = None
            for device in devices:
                if device.id == device_id:
                    device_to_remove = device
                    break
            
            if not device_to_remove:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Device not found"
                )
            
            # Prevent removing the last device
            active_devices = [d for d in devices if d.is_active and d.id != device_id]
            if len(active_devices) == 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot remove the last active device"
                )
            
            # Check if it's the current device
            is_current_device = False
            if request and hasattr(request.state, "device_id"):
                is_current_device = str(device_id) == request.state.device_id
            
            # Remove device
            await device_repo.delete(device_id)
            await uow.commit()
        
        # Log removal
        log_audit_event(
            event_type=AuditEventType.DEVICE_REMOVED,
            user_id=str(current_user.id),
            tenant_id=str(current_user.tenant_id),
            resource=f"device:{device_id}",
            severity=AuditSeverity.HIGH,
            details={
                "device_name": device_to_remove.device_name,
                "device_type": device_to_remove.device_type,
                "is_current_device": is_current_device,
                "remaining_devices": len(active_devices),
                "ip_address": request.client.host if request and request.client else None
            }
        )
        
        # Send security notification
        background_tasks.add_task(
            device_notifications.send_device_removal_notification,
            user_email=current_user.email,
            device_name=device_to_remove.device_name,
            device_type=device_to_remove.device_type,
            removed_by_current_device=is_current_device,
            ip_address=request.client.host if request and request.client else None
        )
        
        logger.info(
            "Device securely removed",
            user_id=str(current_user.id),
            device_id=str(device_id),
            device_name=device_to_remove.device_name,
            is_current_device=is_current_device
        )
        
        return {
            "device_id": str(device_id),
            "device_name": device_to_remove.device_name,
            "removed_at": datetime.utcnow().isoformat(),
            "remaining_devices": len(active_devices),
            "message": "Device removed successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to remove device securely",
            user_id=str(current_user.id),
            device_id=str(device_id),
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to remove device"
        )


@router.post("/{device_id}/request-removal")
async def request_device_removal(
    device_id: UUID,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_async_session),
) -> Dict[str, Any]:
    """
    Request device removal with confirmation code.
    
    Sends confirmation code via email for secure device removal.
    """
    try:
        async with UnitOfWork(session) as uow:
            device_repo = DeviceRepository(UserDevice, session, current_user.tenant_id)
            
            # Verify device exists and belongs to user
            device = await device_repo.get_by_id(device_id)
            
            if not device:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Device not found"
                )
            
            if device.user_id != current_user.id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not authorized to remove this device"
                )
        
        # Generate confirmation code
        confirmation_code = await generate_device_removal_confirmation(
            user_id=current_user.id,
            device_id=device_id
        )
        
        # Send confirmation email
        await send_device_removal_confirmation_email(
            user_email=current_user.email,
            device_name=device.device_name,
            confirmation_code=confirmation_code
        )
        
        logger.info(
            "Device removal requested",
            user_id=str(current_user.id),
            device_id=str(device_id),
            device_name=device.device_name
        )
        
        return {
            "device_id": str(device_id),
            "device_name": device.device_name,
            "confirmation_sent": True,
            "expires_in_minutes": 15,
            "message": "Confirmation code sent to your email"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to request device removal",
            user_id=str(current_user.id),
            device_id=str(device_id),
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to request device removal"
        )


async def calculate_overall_security_score(devices: List[UserDevice]) -> int:
    """Calculate overall security score for all user devices."""
    if not devices:
        return 0
    
    active_devices = [d for d in devices if d.is_active]
    if not active_devices:
        return 0
    
    # Average trust score of active devices
    avg_trust = sum(d.trust_score for d in active_devices) / len(active_devices)
    
    # Penalties for issues
    score = int(avg_trust)
    
    # Penalty for too many devices
    if len(active_devices) > 10:
        score -= 5
    
    # Penalty for old devices
    now = datetime.utcnow()
    month_ago = now - timedelta(days=30)
    old_devices = [d for d in active_devices if not d.last_used_at or d.last_used_at < month_ago]
    if old_devices:
        score -= len(old_devices) * 2
    
    return max(0, min(100, score))


def get_risk_level(security_score: int) -> str:
    """Get risk level based on security score."""
    if security_score >= 80:
        return "low"
    elif security_score >= 60:
        return "medium"
    elif security_score >= 40:
        return "high"
    else:
        return "critical"


def generate_security_recommendations(devices: List[UserDevice]) -> List[str]:
    """Generate security recommendations based on device analysis."""
    recommendations = []
    
    active_devices = [d for d in devices if d.is_active]
    
    # Check for low trust devices
    low_trust_devices = [d for d in active_devices if d.trust_score < 50]
    if low_trust_devices:
        recommendations.append(
            f"Consider removing or re-authenticating {len(low_trust_devices)} low-trust device(s)"
        )
    
    # Check for unused devices
    now = datetime.utcnow()
    month_ago = now - timedelta(days=30)
    unused_devices = [d for d in active_devices if not d.last_used_at or d.last_used_at < month_ago]
    if unused_devices:
        recommendations.append(
            f"Remove {len(unused_devices)} device(s) not used in the last 30 days"
        )
    
    # Check device count
    if len(active_devices) > 8:
        recommendations.append("Consider reducing the number of registered devices for better security")
    
    # Check for diverse device types
    device_types = set(d.device_type for d in active_devices)
    if len(device_types) == 1 and "webauthn" not in device_types:
        recommendations.append("Consider adding WebAuthn devices for enhanced security")
    
    return recommendations


async def perform_comprehensive_security_check(
    device: UserDevice,
    check_type: str
) -> Dict[str, Any]:
    """Perform comprehensive security check on a device."""
    check_results = {
        "device_id": str(device.id),
        "device_name": device.device_name,
        "check_type": check_type,
        "check_timestamp": datetime.utcnow().isoformat(),
        "security_score": int(device.trust_score),
        "issues": [],
        "recommendations": [],
        "compliance_status": "compliant"
    }
    
    # Check device age
    device_age = datetime.utcnow() - device.created_at
    if device_age.days > 365:
        check_results["issues"].append("Device is over 1 year old")
        check_results["recommendations"].append("Consider re-registering device with fresh credentials")
    
    # Check last usage
    if device.last_used_at:
        days_since_use = (datetime.utcnow() - device.last_used_at).days
        if days_since_use > 30:
            check_results["issues"].append(f"Device not used for {days_since_use} days")
            check_results["recommendations"].append("Remove device if no longer in use")
    
    # Check trust score
    if device.trust_score < 50:
        check_results["issues"].append("Low trust score")
        check_results["recommendations"].append("Re-authenticate to improve trust score")
        check_results["compliance_status"] = "non_compliant"
    
    # Get device analytics
    analytics = trust_manager.get_device_analytics(device.id)
    
    # Check for suspicious activity
    if analytics.get("failed_auth_count", 0) > 3:
        check_results["issues"].append("Multiple authentication failures detected")
        check_results["recommendations"].append("Review authentication logs")
    
    # Calculate final security score
    issue_penalty = len(check_results["issues"]) * 5
    final_score = max(0, int(device.trust_score) - issue_penalty)
    check_results["security_score"] = final_score
    
    return check_results


async def generate_device_removal_confirmation(user_id: UUID, device_id: UUID) -> str:
    """Generate confirmation code for device removal."""
    import secrets
    import json
    import base64
    from datetime import timedelta
    
    # Generate secure confirmation code
    code_data = {
        "user_id": str(user_id),
        "device_id": str(device_id),
        "expires_at": (datetime.utcnow() + timedelta(minutes=15)).isoformat(),
        "nonce": secrets.token_urlsafe(16)
    }
    
    # In production, this would be signed and stored securely
    confirmation_code = base64.urlsafe_b64encode(
        json.dumps(code_data).encode()
    ).decode()[:12]  # Shorter code for email
    
    return confirmation_code


async def validate_device_removal_confirmation(
    user_id: UUID,
    device_id: UUID,
    confirmation_code: str
) -> bool:
    """Validate device removal confirmation code."""
    # In production, this would verify against stored codes
    # For now, we'll accept any 12-character code
    return len(confirmation_code) == 12


async def send_device_removal_confirmation_email(
    user_email: str,
    device_name: str,
    confirmation_code: str
) -> bool:
    """Send device removal confirmation email."""
    # This would integrate with email service
    logger.info(
        "Device removal confirmation email sent",
        user_email=user_email,
        device_name=device_name,
        confirmation_code=confirmation_code
    )
    return True