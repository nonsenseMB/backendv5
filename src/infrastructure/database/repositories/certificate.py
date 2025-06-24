"""Repository for device certificate management."""
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from sqlalchemy import and_, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from src.infrastructure.database.models.auth import DeviceCertificate
from src.infrastructure.database.repositories.base import BaseRepository
from src.core.logging import get_logger

logger = get_logger(__name__)


class CertificateRepository(BaseRepository[DeviceCertificate]):
    """Repository for managing device certificates."""
    
    def __init__(
        self,
        model: type[DeviceCertificate],
        session: AsyncSession,
        tenant_id: Optional[UUID] = None
    ):
        """Initialize certificate repository."""
        super().__init__(model, session, tenant_id)
    
    async def get_by_serial_number(
        self,
        serial_number: str
    ) -> Optional[DeviceCertificate]:
        """
        Get certificate by serial number.
        
        Args:
            serial_number: Certificate serial number
            
        Returns:
            Certificate if found, None otherwise
        """
        try:
            query = select(self.model).where(
                self.model.serial_number == serial_number
            ).options(joinedload(self.model.device))
            
            result = await self.session.execute(query)
            certificate = result.scalar_one_or_none()
            
            if certificate:
                logger.debug(
                    "Found certificate by serial",
                    serial_number=serial_number,
                    certificate_id=str(certificate.id)
                )
            
            return certificate
            
        except Exception as e:
            logger.error(
                "Failed to get certificate by serial",
                serial_number=serial_number,
                error=str(e),
                exc_info=True
            )
            raise
    
    async def get_by_fingerprint(
        self,
        fingerprint_sha256: str
    ) -> Optional[DeviceCertificate]:
        """
        Get certificate by SHA256 fingerprint.
        
        Args:
            fingerprint_sha256: SHA256 fingerprint (hex)
            
        Returns:
            Certificate if found, None otherwise
        """
        try:
            query = select(self.model).where(
                self.model.fingerprint_sha256 == fingerprint_sha256.lower()
            ).options(joinedload(self.model.device))
            
            result = await self.session.execute(query)
            certificate = result.scalar_one_or_none()
            
            return certificate
            
        except Exception as e:
            logger.error(
                "Failed to get certificate by fingerprint",
                fingerprint=fingerprint_sha256[:16] + "...",
                error=str(e),
                exc_info=True
            )
            raise
    
    async def get_device_certificates(
        self,
        device_id: UUID,
        active_only: bool = True,
        include_revoked: bool = False
    ) -> List[DeviceCertificate]:
        """
        Get all certificates for a device.
        
        Args:
            device_id: Device ID
            active_only: Whether to return only active certificates
            include_revoked: Whether to include revoked certificates
            
        Returns:
            List of certificates
        """
        try:
            query = select(self.model).where(
                self.model.device_id == device_id
            )
            
            if active_only:
                query = query.where(self.model.is_active == True)
            
            if not include_revoked:
                query = query.where(self.model.revoked == False)
            
            # Order by creation date (newest first)
            query = query.order_by(self.model.created_at.desc())
            
            result = await self.session.execute(query)
            certificates = result.scalars().all()
            
            logger.debug(
                "Retrieved device certificates",
                device_id=str(device_id),
                certificate_count=len(certificates),
                active_only=active_only,
                include_revoked=include_revoked
            )
            
            return certificates
            
        except Exception as e:
            logger.error(
                "Failed to get device certificates",
                device_id=str(device_id),
                error=str(e),
                exc_info=True
            )
            raise
    
    async def get_expiring_certificates(
        self,
        days_before_expiry: int = 30
    ) -> List[DeviceCertificate]:
        """
        Get certificates expiring within specified days.
        
        Args:
            days_before_expiry: Days before expiry
            
        Returns:
            List of expiring certificates
        """
        try:
            from datetime import timedelta
            expiry_date = datetime.utcnow() + timedelta(days=days_before_expiry)
            
            query = select(self.model).where(
                and_(
                    self.model.not_after <= expiry_date,
                    self.model.not_after > datetime.utcnow(),
                    self.model.is_active == True,
                    self.model.revoked == False
                )
            ).options(joinedload(self.model.device))
            
            result = await self.session.execute(query)
            certificates = result.scalars().all()
            
            logger.info(
                "Found expiring certificates",
                count=len(certificates),
                days_before_expiry=days_before_expiry
            )
            
            return certificates
            
        except Exception as e:
            logger.error(
                "Failed to get expiring certificates",
                error=str(e),
                exc_info=True
            )
            raise
    
    async def revoke_certificate(
        self,
        certificate_id: UUID,
        reason: str = "unspecified",
        revoked_by: Optional[UUID] = None
    ) -> DeviceCertificate:
        """
        Revoke a certificate.
        
        Args:
            certificate_id: Certificate ID
            reason: Revocation reason
            revoked_by: User who revoked the certificate
            
        Returns:
            Revoked certificate
        """
        try:
            certificate = await self.update(certificate_id, {
                "revoked": True,
                "revoked_at": datetime.utcnow(),
                "revocation_reason": reason,
                "is_active": False,
                "updated_at": datetime.utcnow()
            })
            
            logger.info(
                "Certificate revoked",
                certificate_id=str(certificate_id),
                serial_number=certificate.serial_number,
                reason=reason,
                revoked_by=str(revoked_by) if revoked_by else None
            )
            
            return certificate
            
        except Exception as e:
            logger.error(
                "Failed to revoke certificate",
                certificate_id=str(certificate_id),
                error=str(e),
                exc_info=True
            )
            raise
    
    async def update_ocsp_check(
        self,
        certificate_id: UUID,
        is_revoked: bool,
        ocsp_response: Optional[dict] = None
    ) -> DeviceCertificate:
        """
        Update OCSP check results.
        
        Args:
            certificate_id: Certificate ID
            is_revoked: Whether certificate is revoked
            ocsp_response: OCSP response data
            
        Returns:
            Updated certificate
        """
        try:
            update_data = {
                "last_ocsp_check": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            }
            
            if is_revoked:
                update_data["revoked"] = True
                update_data["is_active"] = False
                if ocsp_response:
                    update_data["revocation_reason"] = ocsp_response.get("reason", "OCSP check")
            
            certificate = await self.update(certificate_id, update_data)
            
            logger.info(
                "Updated OCSP check",
                certificate_id=str(certificate_id),
                is_revoked=is_revoked
            )
            
            return certificate
            
        except Exception as e:
            logger.error(
                "Failed to update OCSP check",
                certificate_id=str(certificate_id),
                error=str(e),
                exc_info=True
            )
            raise
    
    async def update_crl_check(
        self,
        certificate_id: UUID,
        is_revoked: bool,
        crl_response: Optional[dict] = None
    ) -> DeviceCertificate:
        """
        Update CRL check results.
        
        Args:
            certificate_id: Certificate ID
            is_revoked: Whether certificate is revoked
            crl_response: CRL response data
            
        Returns:
            Updated certificate
        """
        try:
            update_data = {
                "last_crl_check": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            }
            
            if is_revoked:
                update_data["revoked"] = True
                update_data["is_active"] = False
                if crl_response:
                    update_data["revocation_reason"] = crl_response.get("reason", "CRL check")
            
            certificate = await self.update(certificate_id, update_data)
            
            logger.info(
                "Updated CRL check",
                certificate_id=str(certificate_id),
                is_revoked=is_revoked
            )
            
            return certificate
            
        except Exception as e:
            logger.error(
                "Failed to update CRL check",
                certificate_id=str(certificate_id),
                error=str(e),
                exc_info=True
            )
            raise
    
    async def approve_certificate(
        self,
        certificate_id: UUID,
        approved_by: UUID,
        compliance_notes: Optional[str] = None
    ) -> DeviceCertificate:
        """
        Approve a certificate for use.
        
        Args:
            certificate_id: Certificate ID
            approved_by: User who approved
            compliance_notes: Compliance notes
            
        Returns:
            Approved certificate
        """
        try:
            certificate = await self.update(certificate_id, {
                "is_trusted": True,
                "trust_chain_verified": True,
                "compliance_checked": True,
                "compliance_notes": compliance_notes or f"Approved by {approved_by}",
                "updated_at": datetime.utcnow()
            })
            
            logger.info(
                "Certificate approved",
                certificate_id=str(certificate_id),
                approved_by=str(approved_by)
            )
            
            return certificate
            
        except Exception as e:
            logger.error(
                "Failed to approve certificate",
                certificate_id=str(certificate_id),
                error=str(e),
                exc_info=True
            )
            raise
    
    async def count_active_certificates(
        self,
        device_id: Optional[UUID] = None
    ) -> int:
        """
        Count active certificates.
        
        Args:
            device_id: Optional device ID filter
            
        Returns:
            Active certificate count
        """
        try:
            query = select(func.count(self.model.id)).where(
                and_(
                    self.model.is_active == True,
                    self.model.revoked == False,
                    self.model.not_after > datetime.utcnow()
                )
            )
            
            if device_id:
                query = query.where(self.model.device_id == device_id)
            
            result = await self.session.execute(query)
            count = result.scalar() or 0
            
            return count
            
        except Exception as e:
            logger.error(
                "Failed to count active certificates",
                device_id=str(device_id) if device_id else None,
                error=str(e),
                exc_info=True
            )
            raise
    
    async def cleanup_expired_certificates(
        self,
        days_after_expiry: int = 90
    ) -> int:
        """
        Clean up certificates that have been expired for specified days.
        
        Args:
            days_after_expiry: Days after expiry to wait before cleanup
            
        Returns:
            Number of certificates deactivated
        """
        try:
            from datetime import timedelta
            cutoff_date = datetime.utcnow() - timedelta(days=days_after_expiry)
            
            # Find expired certificates
            query = select(self.model).where(
                and_(
                    self.model.not_after < cutoff_date,
                    self.model.is_active == True
                )
            )
            
            result = await self.session.execute(query)
            certificates = result.scalars().all()
            
            # Deactivate each certificate
            deactivated_count = 0
            for cert in certificates:
                await self.update(cert.id, {
                    "is_active": False,
                    "updated_at": datetime.utcnow()
                })
                deactivated_count += 1
            
            logger.info(
                "Cleaned up expired certificates",
                days_after_expiry=days_after_expiry,
                deactivated_count=deactivated_count
            )
            
            return deactivated_count
            
        except Exception as e:
            logger.error(
                "Failed to cleanup expired certificates",
                error=str(e),
                exc_info=True
            )
            raise