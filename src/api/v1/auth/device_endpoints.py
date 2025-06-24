"""Device authentication endpoints for WebAuthn/Passkey support."""
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies.auth import get_current_user
from src.infrastructure.database.session import get_async_session
from src.api.v1.auth.schemas import (
    AuthenticationOptions,
    DeviceAuthenticationSuccess,
    DeviceAuthenticationVerification,
    DeviceInfo,
    DeviceListResponse,
    DeviceRegistrationOptions,
    DeviceRegistrationSuccess,
    DeviceRegistrationVerification,
    DeviceUpdateRequest,
)
from src.core.auth.device_trust import calculate_trust_score
from src.core.auth.trust_manager import trust_manager
from src.core.config import settings
from src.core.logging import get_logger
from src.core.logging.audit import AuditEventType, AuditSeverity, log_audit_event
from src.infrastructure.database.models.auth import User, UserDevice
from src.infrastructure.auth.challenge_store import ChallengeStore
from src.infrastructure.auth.webauthn_manager import WebAuthnManager
from src.infrastructure.cache import get_redis_client
from src.infrastructure.database.repositories.device import DeviceRepository
from src.infrastructure.database.unit_of_work import UnitOfWork

logger = get_logger(__name__)

# Create device router
router = APIRouter(prefix="/device", tags=["device-authentication"])


@router.post("/register/options", response_model=DeviceRegistrationOptions)
async def generate_registration_options(
    request: Request,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_async_session),
) -> DeviceRegistrationOptions:
    """
    Generate registration options for a new device.
    
    This initiates the WebAuthn registration ceremony by providing
    a challenge and configuration for the client.
    """
    try:
        # Initialize managers
        redis_client = await get_redis_client()
        challenge_store = ChallengeStore(redis_client)
        webauthn_manager = WebAuthnManager()
        
        # Get existing user devices to exclude
        async with UnitOfWork(session) as uow:
            device_repo = DeviceRepository(UserDevice, session, current_user.tenant_id)
            existing_devices = await device_repo.get_user_devices(current_user.id)
            
            # Create exclude credentials list
            exclude_credentials = [
                {
                    "type": "public-key",
                    "id": device.credential_id
                }
                for device in existing_devices
            ]
        
        # Generate registration options
        options = await webauthn_manager.generate_registration_options(
            user_id=str(current_user.id),
            user_name=current_user.email,
            user_display_name=current_user.full_name or current_user.email,
            exclude_credentials=exclude_credentials
        )
        
        # Store challenge for verification
        await challenge_store.store_challenge(
            user_id=str(current_user.id),
            challenge=options.challenge,
            challenge_type="registration"
        )
        
        # Log the registration attempt
        logger.info(
            "Device registration initiated",
            user_id=str(current_user.id),
            user_email=current_user.email,
            exclude_count=len(exclude_credentials)
        )
        
        return options
        
    except Exception as e:
        logger.error(
            "Failed to generate registration options",
            user_id=str(current_user.id),
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate registration options"
        )


@router.post("/register", response_model=DeviceRegistrationSuccess)
async def complete_device_registration(
    request: Request,
    verification: DeviceRegistrationVerification,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_async_session),
) -> DeviceRegistrationSuccess:
    """
    Complete device registration with attestation verification.
    
    This verifies the registration response and stores the device credentials.
    """
    try:
        # Initialize managers
        redis_client = await get_redis_client()
        challenge_store = ChallengeStore(redis_client)
        webauthn_manager = WebAuthnManager()
        
        # Retrieve and validate challenge
        stored_challenge = await challenge_store.retrieve_challenge(
            user_id=str(current_user.id),
            challenge_type="registration"
        )
        
        if not stored_challenge:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Registration challenge expired or not found"
            )
        
        # Verify registration
        verification_result = await webauthn_manager.verify_registration(
            credential=verification,
            challenge=stored_challenge,
            user_id=str(current_user.id)
        )
        
        if not verification_result.verified:
            logger.warning(
                "Device registration verification failed",
                user_id=str(current_user.id),
                credential_id=verification.id
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Device registration verification failed"
            )
        
        # Extract device information
        user_agent = request.headers.get("User-Agent", "")
        device_name = webauthn_manager.generate_device_name(user_agent)
        
        # Calculate initial trust score
        trust_score = calculate_trust_score(
            attestation_type=verification_result.attestation_type,
            authenticator_attachment=verification.authenticator_attachment,
            aaguid=verification_result.aaguid
        )
        
        # Store device in database
        async with UnitOfWork(session) as uow:
            device_repo = DeviceRepository(UserDevice, session, current_user.tenant_id)
            
            device = await device_repo.create({
                "id": uuid4(),
                "user_id": current_user.id,
                "device_name": device_name,
                "device_type": "webauthn",
                "device_id": verification.id,  # Use as device_id
                "credential_id": verification.id,
                "public_key": verification_result.public_key,
                "attestation_object": verification_result.attestation_data,
                "sign_count": verification_result.sign_count or 0,
                "trust_score": float(trust_score),
                "is_trusted": trust_score >= 80,
                "user_agent": user_agent,
            })
            
            await uow.commit()
        
        # Log successful registration
        log_audit_event(
            event_type=AuditEventType.DEVICE_REGISTERED,
            user_id=str(current_user.id),
            tenant_id=str(current_user.tenant_id),
            severity=AuditSeverity.MEDIUM,
            details={
                "device_id": str(device.id),
                "device_name": device_name,
                "device_type": "webauthn",
                "trust_level": trust_score,
                "attestation_type": verification_result.attestation_type
            }
        )
        
        logger.info(
            "Device registered successfully",
            user_id=str(current_user.id),
            device_id=str(device.id),
            device_name=device_name,
            trust_level=trust_score
        )
        
        return DeviceRegistrationSuccess(
            device_id=device.id,
            device_name=device_name,
            trust_level=trust_score
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Device registration failed",
            user_id=str(current_user.id),
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Device registration failed"
        )


@router.get("/", response_model=DeviceListResponse)
async def list_user_devices(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_async_session),
    request: Request = None,
) -> DeviceListResponse:
    """
    List all registered devices for the current user.
    
    Returns device information including trust levels and last usage.
    """
    try:
        async with UnitOfWork(session) as uow:
            device_repo = DeviceRepository(UserDevice, session, current_user.tenant_id)
            devices = await device_repo.get_user_devices(current_user.id)
            
            # Get current device ID from request if available
            current_device_id = None
            if request and hasattr(request.state, "device_id"):
                current_device_id = request.state.device_id
            
            # Convert to response models
            device_infos = []
            for device in devices:
                device_info = DeviceInfo(
                    id=device.id,
                    name=device.device_name,
                    type=device.device_type,
                    trust_level=int(device.trust_score),
                    last_used=device.last_used_at or device.created_at,
                    created_at=device.created_at,
                    is_current=(str(device.id) == current_device_id),
                    platform=None,  # Can extract from user_agent if needed
                    browser=None,   # Can extract from user_agent if needed
                    aaguid=None,    # Not stored in UserDevice model
                    attestation_type=None  # Not stored in UserDevice model
                )
                device_infos.append(device_info)
            
            # Sort by last used (most recent first)
            device_infos.sort(key=lambda d: d.last_used, reverse=True)
            
            logger.info(
                "Listed user devices",
                user_id=str(current_user.id),
                device_count=len(device_infos)
            )
            
            return DeviceListResponse(
                devices=device_infos,
                total=len(device_infos)
            )
            
    except Exception as e:
        logger.error(
            "Failed to list user devices",
            user_id=str(current_user.id),
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve devices"
        )


@router.put("/{device_id}", response_model=DeviceInfo)
async def update_device(
    device_id: UUID,
    update_request: DeviceUpdateRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_async_session),
) -> DeviceInfo:
    """
    Update device information.
    
    Currently only supports updating the device name.
    """
    try:
        async with UnitOfWork(session) as uow:
            device_repo = DeviceRepository(UserDevice, session, current_user.tenant_id)
            
            # Get the device
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
                    detail="Not authorized to update this device"
                )
            
            # Update device
            update_data = {}
            if update_request.name is not None:
                update_data["device_name"] = update_request.name
            
            if update_data:
                device = await device_repo.update(device_id, update_data)
                await uow.commit()
                
                logger.info(
                    "Device updated",
                    user_id=str(current_user.id),
                    device_id=str(device_id),
                    updates=list(update_data.keys())
                )
            
            return DeviceInfo(
                id=device.id,
                name=device.device_name,
                type=device.device_type,
                trust_level=int(device.trust_score),
                last_used=device.last_used_at or device.created_at,
                created_at=device.created_at,
                is_current=False,
                platform=None,
                browser=None,
                aaguid=None,
                attestation_type=None
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to update device",
            user_id=str(current_user.id),
            device_id=str(device_id),
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update device"
        )


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(
    device_id: UUID,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_async_session),
    request: Request = None,
) -> None:
    """
    Delete a registered device.
    
    Requires the user to have at least one other device registered
    to prevent lockout. Cannot delete the currently used device.
    """
    try:
        async with UnitOfWork(session) as uow:
            device_repo = DeviceRepository(UserDevice, session, current_user.tenant_id)
            
            # Get all user devices
            devices = await device_repo.get_user_devices(current_user.id)
            
            # Check if device exists and belongs to user
            device_to_delete = None
            for device in devices:
                if device.id == device_id:
                    device_to_delete = device
                    break
            
            if not device_to_delete:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Device not found"
                )
            
            # Prevent deleting the last device
            if len(devices) <= 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot delete the last registered device"
                )
            
            # Prevent deleting current device
            if request and hasattr(request.state, "device_id"):
                if str(device_id) == request.state.device_id:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Cannot delete the currently used device"
                    )
            
            # Delete the device
            await device_repo.delete(device_id)
            await uow.commit()
            
            # Log the deletion
            log_audit_event(
                event_type=AuditEventType.DEVICE_REMOVED,
                user_id=str(current_user.id),
                tenant_id=str(current_user.tenant_id),
                severity=AuditSeverity.HIGH,
                details={
                    "device_id": str(device_id),
                    "device_name": device_to_delete.device_name,
                    "remaining_devices": len(devices) - 1
                }
            )
            
            logger.info(
                "Device deleted",
                user_id=str(current_user.id),
                device_id=str(device_id),
                device_name=device_to_delete.device_name
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to delete device",
            user_id=str(current_user.id),
            device_id=str(device_id),
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete device"
        )


@router.post("/login/options", response_model=AuthenticationOptions)
async def generate_authentication_options(
    request: Request,
    session: AsyncSession = Depends(get_async_session),
) -> AuthenticationOptions:
    """
    Generate authentication options for device login.
    
    This endpoint is public as it initiates the authentication flow.
    The user identifier should be provided via a separate mechanism.
    """
    try:
        # Get user identifier from request (e.g., from a session cookie or initial auth step)
        # For now, we'll require a user email in the request header
        user_email = request.headers.get("X-User-Email")
        if not user_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User identifier required"
            )
        
        # Initialize managers
        redis_client = await get_redis_client()
        challenge_store = ChallengeStore(redis_client)
        webauthn_manager = WebAuthnManager()
        
        # Look up user and their devices
        from src.infrastructure.database.repositories.user import UserRepository
        async with UnitOfWork(session) as uow:
            user_repo = UserRepository(User, session, None)  # No tenant context yet
            user = await user_repo.get_by_email(user_email)
            
            if not user:
                # Don't reveal if user exists
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication failed"
                )
            
            # Get user's devices
            device_repo = DeviceRepository(UserDevice, session, user.tenant_id)
            devices = await device_repo.get_user_devices(user.id)
            
            if not devices:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No devices registered"
                )
            
            # Create allow credentials list
            allow_credentials = [
                {
                    "type": "public-key",
                    "id": device.credential_id
                }
                for device in devices
            ]
        
        # Generate authentication options
        options = await webauthn_manager.generate_authentication_options(
            allow_credentials=allow_credentials
        )
        
        # Store challenge with user context
        await challenge_store.store_challenge(
            user_id=str(user.id),
            challenge=options.challenge,
            challenge_type="authentication"
        )
        
        logger.info(
            "Authentication options generated",
            user_email=user_email,
            device_count=len(allow_credentials)
        )
        
        return options
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to generate authentication options",
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate authentication options"
        )


@router.post("/login", response_model=DeviceAuthenticationSuccess)
async def authenticate_with_device(
    request: Request,
    verification: DeviceAuthenticationVerification,
    session: AsyncSession = Depends(get_async_session),
) -> DeviceAuthenticationSuccess:
    """
    Complete device authentication and issue tokens.
    
    Verifies the authentication response and creates a session.
    """
    try:
        # Initialize managers
        redis_client = await get_redis_client()
        challenge_store = ChallengeStore(redis_client)
        webauthn_manager = WebAuthnManager()
        
        # Look up device by credential ID
        async with UnitOfWork(session) as uow:
            device_repo = DeviceRepository(UserDevice, session, None)  # No tenant context yet
            device = await device_repo.get_by_credential_id(verification.id)
            
            if not device:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication failed"
                )
            
            # Get user
            user_repo = UserRepository(User, session, device.tenant_id)
            user = await user_repo.get_by_id(device.user_id)
            
            if not user or not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication failed"
                )
            
            # Retrieve challenge
            stored_challenge = await challenge_store.retrieve_challenge(
                user_id=str(user.id),
                challenge_type="authentication"
            )
            
            if not stored_challenge:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Authentication challenge expired"
                )
            
            # Verify authentication
            verification_result = await webauthn_manager.verify_authentication(
                credential=verification,
                challenge=stored_challenge,
                public_key=device.public_key,
                sign_count=device.sign_count or 0
            )
            
            if not verification_result.verified:
                logger.warning(
                    "Authentication verification failed",
                    user_id=str(user.id),
                    device_id=str(device.id)
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication failed"
                )
            
            # Update device last used and sign count
            await device_repo.update_last_used(
                device.id,
                new_sign_count=verification_result.new_sign_count
            )
            await uow.commit()
        
        # Generate tokens
        from src.core.auth.jwt_manager import create_access_token
        access_token = create_access_token(
            user_id=str(user.id),
            tenant_id=str(user.tenant_id),
            device_id=str(device.id),
            permissions=user.permissions
        )
        
        # Create session
        from src.infrastructure.auth.session_manager import get_session_manager
        session_manager = await get_session_manager()
        session_data = await session_manager.create_session(
            user_id=str(user.id),
            tenant_id=str(user.tenant_id),
            device_id=str(device.id),
            metadata={
                "device_name": device.device_name,
                "device_type": device.device_type,
                "trust_level": device.trust_level
            }
        )
        
        # Log successful authentication
        log_audit_event(
            event_type=AuditEventType.AUTH_LOGIN_SUCCESS,
            user_id=str(user.id),
            tenant_id=str(user.tenant_id),
            severity=AuditSeverity.LOW,
            details={
                "device_id": str(device.id),
                "device_name": device.device_name,
                "authentication_method": "webauthn"
            }
        )
        
        logger.info(
            "Device authentication successful",
            user_id=str(user.id),
            device_id=str(device.id),
            device_name=device.device_name
        )
        
        return DeviceAuthenticationSuccess(
            access_token=access_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            device_id=device.id,
            refresh_token=session_data.get("session_id") if settings.ENABLE_REFRESH_TOKENS else None
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Device authentication failed",
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication failed"
        )


@router.post("/{device_id}/verify")
async def verify_device_trust(
    device_id: UUID,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_async_session),
) -> dict:
    """
    Re-verify device trust and recalculate trust score.
    
    This can be used to refresh a device's trust level based on
    current usage patterns and analytics.
    """
    try:
        async with UnitOfWork(session) as uow:
            device_repo = DeviceRepository(UserDevice, session, current_user.tenant_id)
            
            # Get the device
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
                    detail="Not authorized to verify this device"
                )
            
            # Get device analytics
            analytics = trust_manager.get_device_analytics(device_id)
            
            # Apply trust decay based on last usage
            current_score = trust_manager.calculate_trust_decay(
                current_score=int(device.trust_score),
                last_used=device.last_used_at or device.created_at
            )
            
            # Adjust for behavior
            adjusted_score, reasons = trust_manager.adjust_trust_for_behavior(
                current_score=current_score,
                device_analytics=analytics
            )
            
            # Update device trust score
            if adjusted_score != int(device.trust_score):
                await device_repo.update(device_id, {
                    "trust_score": float(adjusted_score),
                    "is_trusted": adjusted_score >= 80
                })
                await uow.commit()
                
                logger.info(
                    "Device trust verified and updated",
                    user_id=str(current_user.id),
                    device_id=str(device_id),
                    old_score=int(device.trust_score),
                    new_score=adjusted_score,
                    reasons=reasons
                )
            
            # Get policy for new score
            policy = trust_manager.get_device_policy(adjusted_score)
            
            return {
                "device_id": str(device_id),
                "device_name": device.device_name,
                "trust_score": adjusted_score,
                "trust_level": policy["trust_level_name"],
                "policy": policy,
                "adjustment_reasons": reasons,
                "analytics": analytics
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to verify device trust",
            user_id=str(current_user.id),
            device_id=str(device_id),
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify device trust"
        )


@router.get("/{device_id}/trust-report")
async def get_device_trust_report(
    device_id: UUID,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_async_session),
) -> dict:
    """
    Get comprehensive trust report for a device.
    
    Returns detailed trust information including score breakdown,
    analytics, and policy recommendations.
    """
    try:
        async with UnitOfWork(session) as uow:
            device_repo = DeviceRepository(UserDevice, session, current_user.tenant_id)
            
            # Get the device
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
                    detail="Not authorized to view this device"
                )
            
            # Generate trust report
            device_info = {
                "device_name": device.device_name,
                "device_type": device.device_type,
                "created_at": device.created_at.isoformat(),
                "last_used": (device.last_used_at or device.created_at).isoformat(),
                "user_agent": device.user_agent
            }
            
            report = trust_manager.generate_trust_report(
                device_id=device_id,
                trust_score=int(device.trust_score),
                device_info=device_info
            )
            
            logger.info(
                "Generated device trust report",
                user_id=str(current_user.id),
                device_id=str(device_id)
            )
            
            return report
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to generate trust report",
            user_id=str(current_user.id),
            device_id=str(device_id),
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate trust report"
        )


@router.get("/trust-policies")
async def get_trust_policies(
    current_user: User = Depends(get_current_user),
) -> dict:
    """
    Get available trust policies and their requirements.
    
    This helps users understand what trust levels mean and
    how to improve their device trust.
    """
    try:
        policies = {
            "high_trust": {
                "threshold": trust_manager.HIGH_TRUST_THRESHOLD,
                "policy": trust_manager.POLICIES["high_trust"],
                "description": "High trust devices have strong attestation and consistent usage patterns"
            },
            "medium_trust": {
                "threshold": trust_manager.MEDIUM_TRUST_THRESHOLD,
                "policy": trust_manager.POLICIES["medium_trust"],
                "description": "Medium trust devices have basic security features and reasonable usage"
            },
            "low_trust": {
                "threshold": 0,
                "policy": trust_manager.POLICIES["low_trust"],
                "description": "Low trust devices have minimal security verification"
            }
        }
        
        return {
            "policies": policies,
            "trust_decay_rate": trust_manager.TRUST_DECAY_RATE,
            "min_trust_score": trust_manager.MIN_TRUST_SCORE,
            "max_trust_score": trust_manager.MAX_TRUST_SCORE
        }
        
    except Exception as e:
        logger.error(
            "Failed to get trust policies",
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve trust policies"
        )