"""X.509 certificate validation for device authentication."""
import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

import httpx
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, dsa
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.x509.ocsp import OCSPResponseStatus, load_der_ocsp_response

from src.core.logging import get_logger
from src.core.logging.audit import AuditEventType, AuditSeverity, log_audit_event

logger = get_logger(__name__)


class CertificateValidator:
    """Validates X.509 certificates for device authentication."""
    
    # Supported key algorithms
    SUPPORTED_KEY_ALGORITHMS = {
        rsa.RSAPublicKey: "RSA",
        ec.EllipticCurvePublicKey: "ECDSA",
        dsa.DSAPublicKey: "DSA"
    }
    
    # Minimum key sizes
    MIN_RSA_KEY_SIZE = 2048
    MIN_ECDSA_KEY_SIZE = 256
    MIN_DSA_KEY_SIZE = 2048
    
    # Certificate usage requirements
    REQUIRED_KEY_USAGE = {
        "digital_signature": True,
        "key_agreement": False,  # Optional
        "key_encipherment": False  # Optional
    }
    
    REQUIRED_EXTENDED_KEY_USAGE = [
        "1.3.6.1.5.5.7.3.2",  # Client Authentication
    ]
    
    @staticmethod
    def validate_certificate(
        cert_pem: str,
        ca_cert_pem: Optional[str] = None,
        check_revocation: bool = True,
        required_cn: Optional[str] = None
    ) -> Tuple[bool, Dict[str, Any], Optional[str]]:
        """
        Validate an X.509 certificate.
        
        Args:
            cert_pem: PEM encoded certificate
            ca_cert_pem: PEM encoded CA certificate for chain validation
            check_revocation: Whether to check revocation status
            required_cn: Required Common Name (if any)
            
        Returns:
            Tuple of (is_valid, cert_info, error_message)
        """
        try:
            # Parse certificate
            cert = x509.load_pem_x509_certificate(
                cert_pem.encode(),
                default_backend()
            )
            
            # Extract certificate information
            cert_info = CertificateValidator._extract_cert_info(cert)
            
            # Basic validation
            is_valid, error = CertificateValidator._validate_basic(cert)
            if not is_valid:
                return False, cert_info, error
            
            # Validate dates
            is_valid, error = CertificateValidator._validate_dates(cert)
            if not is_valid:
                return False, cert_info, error
            
            # Validate key strength
            is_valid, error = CertificateValidator._validate_key_strength(cert)
            if not is_valid:
                return False, cert_info, error
            
            # Validate key usage
            is_valid, error = CertificateValidator._validate_key_usage(cert)
            if not is_valid:
                return False, cert_info, error
            
            # Validate CN if required
            if required_cn:
                is_valid, error = CertificateValidator._validate_common_name(cert, required_cn)
                if not is_valid:
                    return False, cert_info, error
            
            # Validate certificate chain if CA provided
            if ca_cert_pem:
                is_valid, error = CertificateValidator._validate_chain(cert, ca_cert_pem)
                if not is_valid:
                    return False, cert_info, error
                cert_info["trust_chain_verified"] = True
            
            # Check revocation status
            if check_revocation:
                is_revoked, revocation_info = CertificateValidator._check_revocation(cert)
                cert_info["revocation_checked"] = True
                cert_info["is_revoked"] = is_revoked
                cert_info["revocation_info"] = revocation_info
                
                if is_revoked:
                    return False, cert_info, f"Certificate revoked: {revocation_info.get('reason', 'Unknown')}"
            
            logger.info(
                "Certificate validated successfully",
                serial_number=cert_info["serial_number"],
                common_name=cert_info["common_name"]
            )
            
            return True, cert_info, None
            
        except Exception as e:
            logger.error(
                "Certificate validation failed",
                error=str(e),
                exc_info=True
            )
            return False, {}, f"Certificate validation error: {str(e)}"
    
    @staticmethod
    def _extract_cert_info(cert: x509.Certificate) -> Dict[str, Any]:
        """Extract certificate information."""
        info = {
            "serial_number": format(cert.serial_number, 'x'),
            "fingerprint_sha256": hashlib.sha256(
                cert.public_bytes(serialization.Encoding.DER)
            ).hexdigest(),
            "issuer_dn": cert.issuer.rfc4514_string(),
            "subject_dn": cert.subject.rfc4514_string(),
            "not_before": cert.not_valid_before_utc,
            "not_after": cert.not_valid_after_utc,
            "version": cert.version.name,
            "signature_algorithm": cert.signature_algorithm_oid._name
        }
        
        # Extract common name
        try:
            info["common_name"] = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except:
            info["common_name"] = ""
        
        # Extract SANs
        san_dns_names = []
        san_ip_addresses = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for san in san_ext.value:
                if isinstance(san, x509.DNSName):
                    san_dns_names.append(san.value)
                elif isinstance(san, x509.IPAddress):
                    san_ip_addresses.append(str(san.value))
        except:
            pass
        
        info["san_dns_names"] = san_dns_names
        info["san_ip_addresses"] = san_ip_addresses
        
        # Extract key usage
        key_usage = []
        extended_key_usage = []
        
        try:
            ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            ku = ku_ext.value
            if ku.digital_signature:
                key_usage.append("digital_signature")
            if ku.key_agreement:
                key_usage.append("key_agreement")
            if ku.key_encipherment:
                key_usage.append("key_encipherment")
            if hasattr(ku, 'content_commitment') and ku.content_commitment:
                key_usage.append("content_commitment")
            if hasattr(ku, 'data_encipherment') and ku.data_encipherment:
                key_usage.append("data_encipherment")
        except:
            pass
        
        try:
            eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            for usage in eku_ext.value:
                extended_key_usage.append(usage.dotted_string)
        except:
            pass
        
        info["key_usage"] = key_usage
        info["extended_key_usage"] = extended_key_usage
        
        # Extract OCSP and CRL info
        info["ocsp_url"] = CertificateValidator._get_ocsp_url(cert)
        info["crl_distribution_points"] = CertificateValidator._get_crl_points(cert)
        
        # Key info
        public_key = cert.public_key()
        for key_type, key_name in CertificateValidator.SUPPORTED_KEY_ALGORITHMS.items():
            if isinstance(public_key, key_type):
                info["key_algorithm"] = key_name
                if key_name == "RSA":
                    info["key_size"] = public_key.key_size
                elif key_name == "ECDSA":
                    info["key_size"] = public_key.curve.key_size
                elif key_name == "DSA":
                    info["key_size"] = public_key.key_size
                break
        
        return info
    
    @staticmethod
    def _validate_basic(cert: x509.Certificate) -> Tuple[bool, Optional[str]]:
        """Basic certificate validation."""
        # Check version (should be v3 for modern certs)
        if cert.version != x509.Version.v3:
            return False, f"Certificate version {cert.version.name} not supported"
        
        # Check if self-signed (not allowed for device certs)
        if cert.issuer == cert.subject:
            return False, "Self-signed certificates not allowed"
        
        return True, None
    
    @staticmethod
    def _validate_dates(cert: x509.Certificate) -> Tuple[bool, Optional[str]]:
        """Validate certificate dates."""
        now = datetime.now(timezone.utc)
        
        if now < cert.not_valid_before_utc:
            return False, f"Certificate not yet valid (starts {cert.not_valid_before_utc})"
        
        if now > cert.not_valid_after_utc:
            return False, f"Certificate expired ({cert.not_valid_after_utc})"
        
        return True, None
    
    @staticmethod
    def _validate_key_strength(cert: x509.Certificate) -> Tuple[bool, Optional[str]]:
        """Validate key algorithm and strength."""
        public_key = cert.public_key()
        
        if isinstance(public_key, rsa.RSAPublicKey):
            if public_key.key_size < CertificateValidator.MIN_RSA_KEY_SIZE:
                return False, f"RSA key size {public_key.key_size} below minimum {CertificateValidator.MIN_RSA_KEY_SIZE}"
        
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if public_key.curve.key_size < CertificateValidator.MIN_ECDSA_KEY_SIZE:
                return False, f"ECDSA key size {public_key.curve.key_size} below minimum {CertificateValidator.MIN_ECDSA_KEY_SIZE}"
        
        elif isinstance(public_key, dsa.DSAPublicKey):
            if public_key.key_size < CertificateValidator.MIN_DSA_KEY_SIZE:
                return False, f"DSA key size {public_key.key_size} below minimum {CertificateValidator.MIN_DSA_KEY_SIZE}"
        
        else:
            return False, "Unsupported key algorithm"
        
        return True, None
    
    @staticmethod
    def _validate_key_usage(cert: x509.Certificate) -> Tuple[bool, Optional[str]]:
        """Validate key usage extensions."""
        # Check key usage
        try:
            ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            ku = ku_ext.value
            
            # Must have digital signature
            if not ku.digital_signature:
                return False, "Certificate must have digital_signature key usage"
            
        except x509.ExtensionNotFound:
            return False, "Certificate missing key usage extension"
        
        # Check extended key usage
        try:
            eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            eku_oids = [usage.dotted_string for usage in eku_ext.value]
            
            # Must have client authentication
            if "1.3.6.1.5.5.7.3.2" not in eku_oids:
                return False, "Certificate must have client authentication extended key usage"
            
        except x509.ExtensionNotFound:
            return False, "Certificate missing extended key usage extension"
        
        return True, None
    
    @staticmethod
    def _validate_common_name(cert: x509.Certificate, required_cn: str) -> Tuple[bool, Optional[str]]:
        """Validate certificate common name."""
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            
            # Support wildcards
            if "*" in required_cn:
                pattern = re.escape(required_cn).replace(r"\*", ".*")
                if not re.match(f"^{pattern}$", cn):
                    return False, f"Common name '{cn}' does not match required pattern '{required_cn}'"
            else:
                if cn != required_cn:
                    return False, f"Common name '{cn}' does not match required '{required_cn}'"
            
        except:
            return False, "Certificate has no common name"
        
        return True, None
    
    @staticmethod
    def _validate_chain(cert: x509.Certificate, ca_cert_pem: str) -> Tuple[bool, Optional[str]]:
        """Validate certificate chain."""
        try:
            # Load CA certificate
            ca_cert = x509.load_pem_x509_certificate(
                ca_cert_pem.encode(),
                default_backend()
            )
            
            # Verify the certificate was issued by the CA
            ca_public_key = ca_cert.public_key()
            
            # Different verification for different key types
            if isinstance(ca_public_key, rsa.RSAPublicKey):
                ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm
                )
            elif isinstance(ca_public_key, ec.EllipticCurvePublicKey):
                ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(cert.signature_hash_algorithm)
                )
            elif isinstance(ca_public_key, dsa.DSAPublicKey):
                ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    cert.signature_hash_algorithm
                )
            else:
                return False, "Unsupported CA key algorithm"
            
            # Verify issuer matches CA subject
            if cert.issuer != ca_cert.subject:
                return False, "Certificate issuer does not match CA subject"
            
            return True, None
            
        except Exception as e:
            return False, f"Chain validation failed: {str(e)}"
    
    @staticmethod
    def _check_revocation(cert: x509.Certificate) -> Tuple[bool, Dict[str, Any]]:
        """Check certificate revocation status."""
        revocation_info = {}
        
        # Try OCSP first (preferred)
        ocsp_url = CertificateValidator._get_ocsp_url(cert)
        if ocsp_url:
            is_revoked, reason = CertificateValidator._check_ocsp(cert, ocsp_url)
            if is_revoked is not None:
                revocation_info["method"] = "OCSP"
                revocation_info["checked_at"] = datetime.utcnow()
                if is_revoked:
                    revocation_info["reason"] = reason
                return is_revoked, revocation_info
        
        # Fall back to CRL
        crl_points = CertificateValidator._get_crl_points(cert)
        if crl_points:
            is_revoked, reason = CertificateValidator._check_crl(cert, crl_points)
            if is_revoked is not None:
                revocation_info["method"] = "CRL"
                revocation_info["checked_at"] = datetime.utcnow()
                if is_revoked:
                    revocation_info["reason"] = reason
                return is_revoked, revocation_info
        
        # No revocation checking possible
        logger.warning(
            "No revocation checking available",
            serial_number=format(cert.serial_number, 'x')
        )
        return False, {"method": "none", "warning": "No revocation checking available"}
    
    @staticmethod
    def _get_ocsp_url(cert: x509.Certificate) -> Optional[str]:
        """Extract OCSP URL from certificate."""
        try:
            aia_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            )
            for access in aia_ext.value:
                if access.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    return access.access_location.value
        except:
            pass
        return None
    
    @staticmethod
    def _get_crl_points(cert: x509.Certificate) -> List[str]:
        """Extract CRL distribution points from certificate."""
        points = []
        try:
            cdp_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.CRL_DISTRIBUTION_POINTS
            )
            for dp in cdp_ext.value:
                if dp.full_name:
                    for name in dp.full_name:
                        if isinstance(name, x509.UniformResourceIdentifier):
                            points.append(name.value)
        except:
            pass
        return points
    
    @staticmethod
    def _check_ocsp(cert: x509.Certificate, ocsp_url: str) -> Tuple[Optional[bool], Optional[str]]:
        """Check certificate status via OCSP."""
        try:
            # This is a simplified implementation
            # In production, you would need the issuer certificate and build a proper OCSP request
            logger.info(
                "OCSP check requested",
                serial_number=format(cert.serial_number, 'x'),
                ocsp_url=ocsp_url
            )
            
            # For now, return None to indicate OCSP not implemented
            # A full implementation would:
            # 1. Build OCSP request
            # 2. Send to OCSP responder
            # 3. Parse OCSP response
            # 4. Return revocation status
            
            return None, None
            
        except Exception as e:
            logger.error(
                "OCSP check failed",
                error=str(e),
                exc_info=True
            )
            return None, None
    
    @staticmethod
    def _check_crl(cert: x509.Certificate, crl_urls: List[str]) -> Tuple[Optional[bool], Optional[str]]:
        """Check certificate status via CRL."""
        for crl_url in crl_urls:
            try:
                logger.info(
                    "Fetching CRL",
                    crl_url=crl_url
                )
                
                # Fetch CRL
                with httpx.Client(timeout=10.0) as client:
                    response = client.get(crl_url)
                    response.raise_for_status()
                
                # Parse CRL
                crl = x509.load_der_x509_crl(response.content, default_backend())
                
                # Check if certificate is revoked
                revoked_cert = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
                
                if revoked_cert:
                    reason = "Unknown"
                    try:
                        reason_ext = revoked_cert.extensions.get_extension_for_oid(
                            x509.oid.CRLEntryExtensionOID.CRL_REASON
                        )
                        reason = reason_ext.value.name
                    except:
                        pass
                    
                    return True, reason
                
                return False, None
                
            except Exception as e:
                logger.error(
                    "CRL check failed",
                    crl_url=crl_url,
                    error=str(e)
                )
                continue
        
        return None, None
    
    @staticmethod
    def generate_certificate_info_for_trust(
        cert_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate certificate information for trust scoring."""
        trust_info = {
            "has_valid_chain": cert_info.get("trust_chain_verified", False),
            "key_algorithm": cert_info.get("key_algorithm", "Unknown"),
            "key_size": cert_info.get("key_size", 0),
            "days_valid": 0,
            "is_ev_cert": False,  # Extended Validation
            "has_ct_logs": False,  # Certificate Transparency
        }
        
        # Calculate days valid
        if "not_after" in cert_info and "not_before" in cert_info:
            validity_period = cert_info["not_after"] - cert_info["not_before"]
            trust_info["days_valid"] = validity_period.days
        
        # Check for EV indicators (simplified)
        if cert_info.get("key_size", 0) >= 2048:
            # In practice, would check EV OIDs in certificate policies
            trust_info["is_ev_cert"] = False
        
        return trust_info