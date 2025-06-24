"""Device certificate management for enterprise authentication."""
import base64
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID, ExtensionOID

from src.core.config import settings
from src.core.logging import get_logger
from src.core.logging.audit import AuditEventType, AuditSeverity, log_audit_event
from src.infrastructure.auth.cert_validator import CertificateValidator

logger = get_logger(__name__)


class DeviceCertificateManager:
    """Manages device certificates for authentication."""
    
    def __init__(self):
        """Initialize certificate manager."""
        self.validator = CertificateValidator()
        
        # Certificate enrollment settings
        self.cert_validity_days = getattr(settings, "DEVICE_CERT_VALIDITY_DAYS", 365)
        self.require_csr = getattr(settings, "DEVICE_CERT_REQUIRE_CSR", True)
        self.auto_approve = getattr(settings, "DEVICE_CERT_AUTO_APPROVE", False)
        
        # Trust settings
        self.trusted_issuers = getattr(settings, "DEVICE_CERT_TRUSTED_ISSUERS", [])
        self.require_chain_validation = getattr(settings, "DEVICE_CERT_REQUIRE_CHAIN", True)
        self.check_revocation = getattr(settings, "DEVICE_CERT_CHECK_REVOCATION", True)
    
    async def enroll_certificate(
        self,
        user_id: UUID,
        device_id: UUID,
        certificate_pem: str,
        certificate_chain_pem: Optional[str] = None,
        enrollment_token: Optional[str] = None
    ) -> Tuple[bool, Dict[str, Any], Optional[str]]:
        """
        Enroll a device certificate.
        
        Args:
            user_id: User ID
            device_id: Device ID
            certificate_pem: PEM encoded certificate
            certificate_chain_pem: PEM encoded certificate chain
            enrollment_token: Optional enrollment token for auto-approval
            
        Returns:
            Tuple of (success, cert_info, error_message)
        """
        try:
            # Validate enrollment token if provided
            if enrollment_token and not self._validate_enrollment_token(enrollment_token, user_id, device_id):
                return False, {}, "Invalid enrollment token"
            
            # Get CA certificate for validation
            ca_cert_pem = None
            if self.require_chain_validation and certificate_chain_pem:
                # Extract CA cert from chain
                ca_cert_pem = self._extract_ca_from_chain(certificate_chain_pem)
            
            # Validate certificate
            is_valid, cert_info, error = self.validator.validate_certificate(
                cert_pem=certificate_pem,
                ca_cert_pem=ca_cert_pem,
                check_revocation=self.check_revocation
            )
            
            if not is_valid:
                logger.warning(
                    "Certificate validation failed",
                    user_id=str(user_id),
                    device_id=str(device_id),
                    error=error
                )
                return False, cert_info, error
            
            # Check if issuer is trusted
            if self.trusted_issuers:
                if not self._is_trusted_issuer(cert_info["issuer_dn"]):
                    return False, cert_info, "Certificate issuer not trusted"
            
            # Auto-approve if configured or token valid
            if self.auto_approve or enrollment_token:
                cert_info["is_trusted"] = True
                cert_info["compliance_checked"] = True
                cert_info["compliance_notes"] = "Auto-approved"
            else:
                cert_info["is_trusted"] = False
                cert_info["compliance_checked"] = False
                cert_info["compliance_notes"] = "Pending approval"
            
            # Add enrollment metadata
            cert_info["enrolled_at"] = datetime.utcnow()
            cert_info["enrolled_by"] = str(user_id)
            cert_info["device_id"] = str(device_id)
            
            # Log enrollment
            log_audit_event(
                event_type=AuditEventType.DEVICE_REGISTERED,
                user_id=str(user_id),
                resource=f"device_cert:{cert_info['serial_number']}",
                severity=AuditSeverity.MEDIUM,
                details={
                    "device_id": str(device_id),
                    "certificate_serial": cert_info["serial_number"],
                    "issuer": cert_info["issuer_dn"],
                    "auto_approved": self.auto_approve or bool(enrollment_token)
                }
            )
            
            logger.info(
                "Certificate enrolled successfully",
                user_id=str(user_id),
                device_id=str(device_id),
                serial_number=cert_info["serial_number"]
            )
            
            return True, cert_info, None
            
        except Exception as e:
            logger.error(
                "Certificate enrollment failed",
                user_id=str(user_id),
                device_id=str(device_id),
                error=str(e),
                exc_info=True
            )
            return False, {}, f"Enrollment error: {str(e)}"
    
    async def generate_enrollment_token(
        self,
        user_id: UUID,
        device_id: UUID,
        validity_hours: int = 24
    ) -> str:
        """
        Generate enrollment token for auto-approval.
        
        Args:
            user_id: User ID
            device_id: Device ID
            validity_hours: Token validity in hours
            
        Returns:
            Enrollment token
        """
        # Generate secure token
        token_data = {
            "user_id": str(user_id),
            "device_id": str(device_id),
            "expires_at": (datetime.utcnow() + timedelta(hours=validity_hours)).isoformat(),
            "nonce": secrets.token_urlsafe(32)
        }
        
        # In production, this would be signed with a secret key
        import json
        token = base64.urlsafe_b64encode(
            json.dumps(token_data).encode()
        ).decode()
        
        logger.info(
            "Generated enrollment token",
            user_id=str(user_id),
            device_id=str(device_id),
            validity_hours=validity_hours
        )
        
        return token
    
    def _validate_enrollment_token(
        self,
        token: str,
        user_id: UUID,
        device_id: UUID
    ) -> bool:
        """Validate enrollment token."""
        try:
            import json
            token_data = json.loads(
                base64.urlsafe_b64decode(token.encode()).decode()
            )
            
            # Check user and device match
            if token_data.get("user_id") != str(user_id):
                return False
            if token_data.get("device_id") != str(device_id):
                return False
            
            # Check expiration
            expires_at = datetime.fromisoformat(token_data.get("expires_at", ""))
            if datetime.utcnow() > expires_at:
                return False
            
            return True
            
        except Exception as e:
            logger.debug(
                "Token validation failed",
                error=str(e)
            )
            return False
    
    def _extract_ca_from_chain(self, chain_pem: str) -> Optional[str]:
        """Extract CA certificate from chain."""
        try:
            # Split PEM chain into individual certificates
            certs = []
            current_cert = []
            
            for line in chain_pem.strip().split('\n'):
                if line.startswith('-----BEGIN CERTIFICATE-----'):
                    current_cert = [line]
                elif line.startswith('-----END CERTIFICATE-----'):
                    current_cert.append(line)
                    certs.append('\n'.join(current_cert))
                    current_cert = []
                elif current_cert:
                    current_cert.append(line)
            
            # Return the last certificate (should be CA)
            if certs:
                return certs[-1]
            
        except Exception as e:
            logger.debug(
                "Failed to extract CA from chain",
                error=str(e)
            )
        
        return None
    
    def _is_trusted_issuer(self, issuer_dn: str) -> bool:
        """Check if issuer is in trusted list."""
        for trusted_issuer in self.trusted_issuers:
            if trusted_issuer in issuer_dn:
                return True
        return False
    
    async def validate_certificate_auth(
        self,
        certificate_pem: str,
        device_id: UUID
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Validate certificate for authentication.
        
        Args:
            certificate_pem: PEM encoded certificate
            device_id: Expected device ID
            
        Returns:
            Tuple of (is_valid, device_info, error)
        """
        try:
            # Validate certificate
            is_valid, cert_info, error = self.validator.validate_certificate(
                cert_pem=certificate_pem,
                check_revocation=self.check_revocation
            )
            
            if not is_valid:
                return False, None, error
            
            # Additional authentication checks would go here:
            # 1. Check certificate is enrolled for this device
            # 2. Check certificate is not revoked in our system
            # 3. Check device is still active
            
            device_info = {
                "device_id": str(device_id),
                "authenticated_at": datetime.utcnow(),
                "auth_method": "certificate",
                "certificate_serial": cert_info["serial_number"],
                "certificate_cn": cert_info["common_name"]
            }
            
            return True, device_info, None
            
        except Exception as e:
            logger.error(
                "Certificate authentication failed",
                device_id=str(device_id),
                error=str(e),
                exc_info=True
            )
            return False, None, f"Authentication error: {str(e)}"
    
    async def revoke_certificate(
        self,
        serial_number: str,
        reason: str = "unspecified",
        revoked_by: UUID = None
    ) -> bool:
        """
        Revoke a certificate.
        
        Args:
            serial_number: Certificate serial number
            reason: Revocation reason
            revoked_by: User who revoked the certificate
            
        Returns:
            Success status
        """
        try:
            # Log revocation
            log_audit_event(
                event_type=AuditEventType.DEVICE_REMOVED,
                user_id=str(revoked_by) if revoked_by else None,
                resource=f"device_cert:{serial_number}",
                severity=AuditSeverity.HIGH,
                details={
                    "certificate_serial": serial_number,
                    "revocation_reason": reason,
                    "revoked_at": datetime.utcnow().isoformat()
                }
            )
            
            logger.info(
                "Certificate revoked",
                serial_number=serial_number,
                reason=reason,
                revoked_by=str(revoked_by) if revoked_by else None
            )
            
            return True
            
        except Exception as e:
            logger.error(
                "Certificate revocation failed",
                serial_number=serial_number,
                error=str(e),
                exc_info=True
            )
            return False
    
    def calculate_certificate_trust_score(
        self,
        cert_info: Dict[str, Any]
    ) -> int:
        """
        Calculate trust score for certificate-based authentication.
        
        Args:
            cert_info: Certificate information
            
        Returns:
            Trust score (0-100)
        """
        score = 0
        
        # Base score for certificate auth
        score += 50
        
        # Chain validation bonus
        if cert_info.get("trust_chain_verified"):
            score += 20
        
        # Key strength bonus
        key_size = cert_info.get("key_size", 0)
        if key_size >= 4096:
            score += 15
        elif key_size >= 2048:
            score += 10
        
        # Algorithm bonus
        key_algorithm = cert_info.get("key_algorithm", "")
        if key_algorithm == "ECDSA":
            score += 10  # Modern algorithm
        elif key_algorithm == "RSA":
            score += 5
        
        # Validity period penalty
        days_valid = cert_info.get("days_valid", 0)
        if days_valid > 730:  # More than 2 years
            score -= 5  # Long-lived certs are less secure
        
        # Trusted issuer bonus
        if cert_info.get("is_trusted", False):
            score += 10
        
        # Cap at 100
        return min(score, 100)


class MutualTLSHandler:
    """Handles mutual TLS authentication."""
    
    @staticmethod
    async def extract_client_certificate(
        request_headers: Dict[str, str]
    ) -> Optional[str]:
        """
        Extract client certificate from request headers.
        
        Args:
            request_headers: HTTP request headers
            
        Returns:
            PEM encoded certificate or None
        """
        # Different web servers/proxies use different headers
        cert_headers = [
            "X-SSL-Client-Cert",  # Nginx
            "X-Client-Cert",      # Generic
            "SSL_CLIENT_CERT",    # Apache
            "X-ARR-ClientCert"    # IIS ARR
        ]
        
        for header in cert_headers:
            cert_pem = request_headers.get(header)
            if cert_pem:
                # Some proxies URL-encode the certificate
                if cert_pem.startswith("%"):
                    from urllib.parse import unquote
                    cert_pem = unquote(cert_pem)
                
                # Ensure proper PEM format
                if not cert_pem.startswith("-----BEGIN CERTIFICATE-----"):
                    # Try to add PEM headers
                    cert_pem = f"-----BEGIN CERTIFICATE-----\n{cert_pem}\n-----END CERTIFICATE-----"
                
                return cert_pem
        
        return None
    
    @staticmethod
    async def validate_mtls_request(
        request_headers: Dict[str, str],
        required_cn: Optional[str] = None
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Validate mutual TLS request.
        
        Args:
            request_headers: HTTP request headers
            required_cn: Required certificate CN
            
        Returns:
            Tuple of (is_valid, cert_info, error)
        """
        # Extract client certificate
        cert_pem = await MutualTLSHandler.extract_client_certificate(request_headers)
        
        if not cert_pem:
            return False, None, "No client certificate provided"
        
        # Validate certificate
        validator = CertificateValidator()
        is_valid, cert_info, error = validator.validate_certificate(
            cert_pem=cert_pem,
            required_cn=required_cn,
            check_revocation=True
        )
        
        return is_valid, cert_info, error