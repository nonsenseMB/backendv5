"""Device certificate management endpoints."""
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies.auth import get_current_user
from src.api.dependencies.trust import require_high_trust
from src.infrastructure.database.session import get_async_session
from src.api.v1.auth.certificate_schemas import (
    CertificateApprovalRequest,
    CertificateEnrollmentRequest,
    CertificateEnrollmentResponse,
    CertificateInfo,
    CertificateListResponse,
    CertificateRevocationRequest,
    CertificateTrustReport,
    CertificateValidationRequest,
    CertificateValidationResponse,
    EnrollmentTokenRequest,
    EnrollmentTokenResponse,
    MutualTLSValidationRequest,
    MutualTLSValidationResponse,
)
from src.core.logging import get_logger
from src.core.logging.audit import AuditEventType, AuditSeverity, log_audit_event
from src.infrastructure.database.models.auth import User, DeviceCertificate
from src.infrastructure.database.repositories.certificate import CertificateRepository
from src.infrastructure.database.repositories.device import DeviceRepository
from src.infrastructure.database.models.auth import UserDevice
from src.infrastructure.database.unit_of_work import UnitOfWork
from src.infrastructure.auth.device_cert import DeviceCertificateManager, MutualTLSHandler

logger = get_logger(__name__)

# Create certificate router
router = APIRouter(prefix="/certificates", tags=["device-certificates"])


@router.post("/enroll", response_model=CertificateEnrollmentResponse)
async def enroll_device_certificate(
    request: Request,
    enrollment: CertificateEnrollmentRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_async_session),
) -> CertificateEnrollmentResponse:
    """
    Enroll a device certificate for authentication.
    
    This allows enterprise devices to register X.509 certificates
    for enhanced authentication and mutual TLS support.
    """
    try:
        cert_manager = DeviceCertificateManager()
        
        # Verify device exists and belongs to user
        async with UnitOfWork(session) as uow:
            device_repo = DeviceRepository(UserDevice, session, current_user.tenant_id)
            device = await device_repo.get_by_id(enrollment.device_id)
            
            if not device:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Device not found"
                )
            
            if device.user_id != current_user.id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not authorized to enroll certificate for this device"
                )
            
            # Enroll certificate
            success, cert_info, error = await cert_manager.enroll_certificate(
                user_id=current_user.id,
                device_id=enrollment.device_id,
                certificate_pem=enrollment.certificate,
                certificate_chain_pem=enrollment.certificate_chain,
                enrollment_token=enrollment.enrollment_token
            )
            
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=error or "Certificate enrollment failed"
                )
            
            # Calculate trust score
            trust_score = cert_manager.calculate_certificate_trust_score(cert_info)
            
            # Store certificate in database
            cert_repo = CertificateRepository(DeviceCertificate, session, current_user.tenant_id)
            
            certificate = await cert_repo.create({
                "id": uuid4(),
                "device_id": enrollment.device_id,
                "certificate": enrollment.certificate,
                "certificate_chain": enrollment.certificate_chain,
                "serial_number": cert_info["serial_number"],
                "fingerprint_sha256": cert_info["fingerprint_sha256"],
                "issuer_dn": cert_info["issuer_dn"],
                "subject_dn": cert_info["subject_dn"],
                "common_name": cert_info["common_name"],
                "san_dns_names": cert_info.get("san_dns_names", []),
                "san_ip_addresses": cert_info.get("san_ip_addresses", []),
                "not_before": cert_info["not_before"],
                "not_after": cert_info["not_after"],
                "key_usage": cert_info.get("key_usage", []),
                "extended_key_usage": cert_info.get("extended_key_usage", []),
                "ocsp_url": cert_info.get("ocsp_url"),
                "crl_distribution_points": cert_info.get("crl_distribution_points", []),
                "is_trusted": cert_info.get("is_trusted", False),
                "trust_chain_verified": cert_info.get("trust_chain_verified", False),
                "compliance_checked": cert_info.get("compliance_checked", False),
                "compliance_notes": cert_info.get("compliance_notes"),
            })
            
            await uow.commit()
        
        # Log enrollment
        log_audit_event(
            event_type=AuditEventType.DEVICE_REGISTERED,
            user_id=str(current_user.id),
            tenant_id=str(current_user.tenant_id),
            resource=f"certificate:{cert_info['serial_number']}",
            severity=AuditSeverity.MEDIUM,
            details={
                "device_id": str(enrollment.device_id),
                "certificate_serial": cert_info["serial_number"],
                "trust_score": trust_score,
                "auto_approved": cert_info.get("is_trusted", False)
            }
        )
        
        logger.info(
            "Certificate enrolled successfully",
            user_id=str(current_user.id),
            device_id=str(enrollment.device_id),
            certificate_id=str(certificate.id),
            trust_score=trust_score
        )
        
        return CertificateEnrollmentResponse(
            certificate_id=certificate.id,
            serial_number=cert_info["serial_number"],
            fingerprint_sha256=cert_info["fingerprint_sha256"],
            common_name=cert_info["common_name"],
            issuer_dn=cert_info["issuer_dn"],
            not_before=cert_info["not_before"],
            not_after=cert_info["not_after"],
            is_trusted=cert_info.get("is_trusted", False),
            trust_score=trust_score,
            status="enrolled" if cert_info.get("is_trusted") else "pending_approval",
            message="Certificate enrolled successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Certificate enrollment failed",
            user_id=str(current_user.id),
            device_id=str(enrollment.device_id),
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Certificate enrollment failed"
        )


@router.get("/device/{device_id}", response_model=CertificateListResponse)
async def list_device_certificates(
    device_id: UUID,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_async_session),
    include_revoked: bool = False,
) -> CertificateListResponse:
    """
    List all certificates for a specific device.
    
    Returns certificate information including trust status,
    validity periods, and revocation status.
    """
    try:
        async with UnitOfWork(session) as uow:
            # Verify device access
            device_repo = DeviceRepository(UserDevice, session, current_user.tenant_id)
            device = await device_repo.get_by_id(device_id)
            
            if not device:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Device not found"
                )
            
            if device.user_id != current_user.id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not authorized to view this device"
                )
            
            # Get certificates
            cert_repo = CertificateRepository(DeviceCertificate, session, current_user.tenant_id)
            certificates = await cert_repo.get_device_certificates(
                device_id=device_id,
                active_only=False,
                include_revoked=include_revoked
            )
            
            # Convert to response models
            cert_infos = []
            active_count = 0
            expired_count = 0
            revoked_count = 0
            
            from datetime import datetime
            now = datetime.utcnow()
            
            for cert in certificates:
                cert_info = CertificateInfo(
                    id=cert.id,
                    device_id=cert.device_id,
                    serial_number=cert.serial_number,
                    fingerprint_sha256=cert.fingerprint_sha256,
                    common_name=cert.common_name,
                    issuer_dn=cert.issuer_dn,
                    subject_dn=cert.subject_dn,
                    not_before=cert.not_before,
                    not_after=cert.not_after,
                    key_usage=cert.key_usage or [],
                    extended_key_usage=cert.extended_key_usage or [],
                    san_dns_names=cert.san_dns_names or [],
                    san_ip_addresses=cert.san_ip_addresses or [],
                    is_active=cert.is_active,
                    is_trusted=cert.is_trusted,
                    revoked=cert.revoked,
                    revoked_at=cert.revoked_at,
                    revocation_reason=cert.revocation_reason,
                    ocsp_url=cert.ocsp_url,
                    crl_distribution_points=cert.crl_distribution_points or [],
                    last_ocsp_check=cert.last_ocsp_check,
                    last_crl_check=cert.last_crl_check,
                    trust_chain_verified=cert.trust_chain_verified,
                    compliance_checked=cert.compliance_checked,
                    compliance_notes=cert.compliance_notes,
                    created_at=cert.created_at,
                    updated_at=cert.updated_at
                )
                cert_infos.append(cert_info)
                
                # Count statuses
                if cert.revoked:
                    revoked_count += 1
                elif cert.not_after < now:
                    expired_count += 1
                elif cert.is_active:
                    active_count += 1
            
            logger.info(
                "Listed device certificates",
                user_id=str(current_user.id),
                device_id=str(device_id),
                total_count=len(cert_infos),
                active_count=active_count
            )
            
            return CertificateListResponse(
                certificates=cert_infos,
                total=len(cert_infos),
                active_count=active_count,
                expired_count=expired_count,
                revoked_count=revoked_count
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to list device certificates",
            user_id=str(current_user.id),
            device_id=str(device_id),
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list certificates"
        )


@router.post("/{certificate_id}/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_certificate(
    certificate_id: UUID,
    revocation: CertificateRevocationRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_async_session),
    _: dict = Depends(require_high_trust),  # Require high trust for revocation
) -> None:
    """
    Revoke a device certificate.
    
    This action immediately invalidates the certificate
    and prevents its use for authentication.
    """
    try:
        async with UnitOfWork(session) as uow:
            cert_repo = CertificateRepository(DeviceCertificate, session, current_user.tenant_id)
            
            # Get certificate
            certificate = await cert_repo.get_by_id(certificate_id)
            
            if not certificate:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Certificate not found"
                )
            
            # Verify device ownership
            device_repo = DeviceRepository(UserDevice, session, current_user.tenant_id)
            device = await device_repo.get_by_id(certificate.device_id)
            
            if not device or device.user_id != current_user.id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not authorized to revoke this certificate"
                )
            
            # Revoke certificate
            await cert_repo.revoke_certificate(
                certificate_id=certificate_id,
                reason=revocation.reason,
                revoked_by=current_user.id
            )
            
            await uow.commit()
        
        # Log revocation
        log_audit_event(
            event_type=AuditEventType.DEVICE_REMOVED,
            user_id=str(current_user.id),
            tenant_id=str(current_user.tenant_id),
            resource=f"certificate:{certificate.serial_number}",
            severity=AuditSeverity.HIGH,
            details={
                "certificate_id": str(certificate_id),
                "serial_number": certificate.serial_number,
                "revocation_reason": revocation.reason
            }
        )
        
        logger.info(
            "Certificate revoked",
            user_id=str(current_user.id),
            certificate_id=str(certificate_id),
            reason=revocation.reason
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to revoke certificate",
            user_id=str(current_user.id),
            certificate_id=str(certificate_id),
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke certificate"
        )


@router.post("/enrollment-token", response_model=EnrollmentTokenResponse)
async def generate_enrollment_token(
    request_data: EnrollmentTokenRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_async_session),
    _: dict = Depends(require_high_trust),  # Require high trust for token generation
) -> EnrollmentTokenResponse:
    """
    Generate an enrollment token for auto-approval.
    
    This token can be used to automatically approve
    certificate enrollment for a specific device.
    """
    try:
        # Verify device ownership
        async with UnitOfWork(session) as uow:
            device_repo = DeviceRepository(UserDevice, session, current_user.tenant_id)
            device = await device_repo.get_by_id(request_data.device_id)
            
            if not device:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Device not found"
                )
            
            if device.user_id != current_user.id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not authorized to generate token for this device"
                )
        
        # Generate token
        cert_manager = DeviceCertificateManager()
        token = await cert_manager.generate_enrollment_token(
            user_id=current_user.id,
            device_id=request_data.device_id,
            validity_hours=request_data.validity_hours
        )
        
        from datetime import timedelta
        expires_at = datetime.utcnow() + timedelta(hours=request_data.validity_hours)
        
        logger.info(
            "Generated enrollment token",
            user_id=str(current_user.id),
            device_id=str(request_data.device_id),
            validity_hours=request_data.validity_hours
        )
        
        return EnrollmentTokenResponse(
            token=token,
            expires_at=expires_at,
            device_id=request_data.device_id
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to generate enrollment token",
            user_id=str(current_user.id),
            device_id=str(request_data.device_id),
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate enrollment token"
        )


@router.post("/validate", response_model=CertificateValidationResponse)
async def validate_certificate(
    validation: CertificateValidationRequest,
    current_user: User = Depends(get_current_user),
) -> CertificateValidationResponse:
    """
    Validate a certificate without enrolling it.
    
    This endpoint allows testing certificate validity
    and trust scoring before enrollment.
    """
    try:
        from src.infrastructure.auth.cert_validator import CertificateValidator
        
        validator = CertificateValidator()
        is_valid, cert_info, error = validator.validate_certificate(
            cert_pem=validation.certificate,
            check_revocation=validation.check_revocation,
            required_cn=validation.required_cn
        )
        
        trust_score = None
        if is_valid:
            cert_manager = DeviceCertificateManager()
            trust_score = cert_manager.calculate_certificate_trust_score(cert_info)
        
        validation_errors = []
        if error:
            validation_errors.append(error)
        
        logger.info(
            "Certificate validation completed",
            user_id=str(current_user.id),
            is_valid=is_valid,
            trust_score=trust_score
        )
        
        return CertificateValidationResponse(
            is_valid=is_valid,
            certificate_info=cert_info if is_valid else None,
            validation_errors=validation_errors,
            trust_score=trust_score
        )
        
    except Exception as e:
        logger.error(
            "Certificate validation failed",
            user_id=str(current_user.id),
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Certificate validation failed"
        )


@router.post("/mtls/validate", response_model=MutualTLSValidationResponse)
async def validate_mutual_tls(
    validation: MutualTLSValidationRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_async_session),
) -> MutualTLSValidationResponse:
    """
    Validate mutual TLS authentication.
    
    This endpoint validates client certificates from
    TLS handshakes and authenticates devices.
    """
    try:
        # Validate the certificate
        handler = MutualTLSHandler()
        is_valid, cert_info, error = await handler.validate_mtls_request(
            request_headers={"X-SSL-Client-Cert": validation.client_certificate},
            required_cn=validation.required_cn
        )
        
        if not is_valid:
            return MutualTLSValidationResponse(
                is_valid=False,
                error=error
            )
        
        # Look up device by certificate
        async with UnitOfWork(session) as uow:
            cert_repo = CertificateRepository(DeviceCertificate, session, current_user.tenant_id)
            certificate = await cert_repo.get_by_fingerprint(cert_info["fingerprint_sha256"])
            
            if not certificate:
                return MutualTLSValidationResponse(
                    is_valid=False,
                    error="Certificate not enrolled"
                )
            
            if certificate.revoked or not certificate.is_active:
                return MutualTLSValidationResponse(
                    is_valid=False,
                    error="Certificate revoked or inactive"
                )
            
            # Get device trust score
            device_repo = DeviceRepository(UserDevice, session, current_user.tenant_id)
            device = await device_repo.get_by_id(certificate.device_id)
            
            trust_score = int(device.trust_score) if device else 0
        
        logger.info(
            "Mutual TLS validation successful",
            user_id=str(current_user.id),
            device_id=str(certificate.device_id),
            certificate_serial=certificate.serial_number
        )
        
        return MutualTLSValidationResponse(
            is_valid=True,
            certificate_info=cert_info,
            device_id=certificate.device_id,
            trust_score=trust_score
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Mutual TLS validation failed",
            user_id=str(current_user.id),
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Mutual TLS validation failed"
        )