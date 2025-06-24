"""Integration tests for certificate endpoints."""
import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from src.infrastructure.auth.device_cert import DeviceCertificateManager
from src.infrastructure.auth.cert_validator import CertificateValidator


class TestCertificateIntegration:
    """Test certificate management integration."""
    
    @pytest.fixture
    def cert_manager(self):
        """Create certificate manager instance."""
        return DeviceCertificateManager()
    
    @pytest.fixture
    def test_certificate(self):
        """Generate test certificate and key."""
        # Generate key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create certificate
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Enterprise"),
            x509.NameAttribute(NameOID.COMMON_NAME, "device-001.example.com"),
        ])
        
        # For testing, we'll create a self-signed cert
        # In production, this would be signed by a CA
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA"),
        ])
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("device-001.example.com"),
                    x509.DNSName("device-001-alt.example.com"),
                ]),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_agreement=False,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=True,
            )
            .add_extension(
                x509.AuthorityInformationAccess([
                    x509.AccessDescription(
                        x509.oid.AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier("http://ocsp.example.com")
                    )
                ]),
                critical=False,
            )
            .add_extension(
                x509.CRLDistributionPoints([
                    x509.DistributionPoint(
                        full_name=[
                            x509.UniformResourceIdentifier("http://crl.example.com/test.crl")
                        ],
                        relative_name=None,
                        crl_issuer=None,
                        reasons=None
                    )
                ]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )
        
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        return {
            "certificate": cert_pem,
            "private_key": key_pem,
            "serial_number": format(cert.serial_number, 'x'),
            "common_name": "device-001.example.com"
        }
    
    @pytest.fixture
    def ca_certificate(self):
        """Generate CA certificate."""
        # Generate CA key
        ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create CA certificate
        ca_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA"),
        ])
        
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_subject)
            .issuer_name(ca_subject)  # Self-signed CA
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_agreement=False,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256(), default_backend())
        )
        
        return ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    
    @pytest.mark.asyncio
    async def test_certificate_enrollment_success(self, cert_manager, test_certificate):
        """Test successful certificate enrollment."""
        user_id = uuid4()
        device_id = uuid4()
        
        success, cert_info, error = await cert_manager.enroll_certificate(
            user_id=user_id,
            device_id=device_id,
            certificate_pem=test_certificate["certificate"]
        )
        
        # Should succeed but not be trusted (no CA validation)
        assert success is True
        assert error is None
        assert cert_info["serial_number"] == test_certificate["serial_number"]
        assert cert_info["common_name"] == test_certificate["common_name"]
        assert "device-001.example.com" in cert_info["san_dns_names"]
        assert cert_info["ocsp_url"] == "http://ocsp.example.com"
        assert "http://crl.example.com/test.crl" in cert_info["crl_distribution_points"]
    
    @pytest.mark.asyncio
    async def test_certificate_enrollment_with_token(self, cert_manager, test_certificate):
        """Test certificate enrollment with auto-approval token."""
        user_id = uuid4()
        device_id = uuid4()
        
        # Generate enrollment token
        token = await cert_manager.generate_enrollment_token(
            user_id=user_id,
            device_id=device_id,
            validity_hours=24
        )
        
        # Enroll with token
        success, cert_info, error = await cert_manager.enroll_certificate(
            user_id=user_id,
            device_id=device_id,
            certificate_pem=test_certificate["certificate"],
            enrollment_token=token
        )
        
        assert success is True
        assert cert_info["is_trusted"] is True
        assert cert_info["compliance_checked"] is True
    
    @pytest.mark.asyncio
    async def test_certificate_enrollment_invalid_token(self, cert_manager, test_certificate):
        """Test certificate enrollment with invalid token."""
        user_id = uuid4()
        device_id = uuid4()
        wrong_device_id = uuid4()
        
        # Generate token for different device
        token = await cert_manager.generate_enrollment_token(
            user_id=user_id,
            device_id=wrong_device_id,
            validity_hours=24
        )
        
        # Try to enroll for different device
        success, cert_info, error = await cert_manager.enroll_certificate(
            user_id=user_id,
            device_id=device_id,
            certificate_pem=test_certificate["certificate"],
            enrollment_token=token
        )
        
        assert success is False
        assert "Invalid enrollment token" in error
    
    @pytest.mark.asyncio
    async def test_certificate_validation_for_auth(self, cert_manager, test_certificate):
        """Test certificate validation for authentication."""
        device_id = uuid4()
        
        is_valid, device_info, error = await cert_manager.validate_certificate_auth(
            certificate_pem=test_certificate["certificate"],
            device_id=device_id
        )
        
        # Should be valid for authentication
        assert is_valid is True
        assert device_info is not None
        assert device_info["auth_method"] == "certificate"
        assert device_info["certificate_serial"] == test_certificate["serial_number"]
        assert device_info["certificate_cn"] == test_certificate["common_name"]
    
    @pytest.mark.asyncio
    async def test_certificate_revocation(self, cert_manager):
        """Test certificate revocation."""
        serial_number = "1234567890abcdef"
        user_id = uuid4()
        
        success = await cert_manager.revoke_certificate(
            serial_number=serial_number,
            reason="key_compromise",
            revoked_by=user_id
        )
        
        assert success is True
    
    def test_certificate_trust_score_calculation(self, cert_manager):
        """Test trust score calculation for certificates."""
        # High trust certificate
        high_trust_info = {
            "trust_chain_verified": True,
            "key_algorithm": "ECDSA",
            "key_size": 256,
            "days_valid": 365,
            "is_trusted": True
        }
        
        score = cert_manager.calculate_certificate_trust_score(high_trust_info)
        assert score >= 80  # Should be high trust
        
        # Low trust certificate
        low_trust_info = {
            "trust_chain_verified": False,
            "key_algorithm": "RSA",
            "key_size": 1024,  # Weak key
            "days_valid": 1095,  # Too long
            "is_trusted": False
        }
        
        score = cert_manager.calculate_certificate_trust_score(low_trust_info)
        assert score < 60  # Should be lower trust
    
    def test_certificate_validator_integration(self, test_certificate):
        """Test certificate validator integration."""
        validator = CertificateValidator()
        
        is_valid, cert_info, error = validator.validate_certificate(
            cert_pem=test_certificate["certificate"],
            check_revocation=False  # Skip for unit test
        )
        
        # Should fail because it's self-signed, but info should be extracted
        assert is_valid is False
        assert "self-signed" in error
        assert cert_info["common_name"] == test_certificate["common_name"]
    
    @pytest.mark.asyncio
    async def test_mutual_tls_handler_integration(self):
        """Test mutual TLS handler integration."""
        from src.infrastructure.auth.device_cert import MutualTLSHandler
        
        # Test with no certificate
        cert_pem = await MutualTLSHandler.extract_client_certificate({})
        assert cert_pem is None
        
        # Test with certificate in header
        test_cert = "-----BEGIN CERTIFICATE-----\nVGVzdA==\n-----END CERTIFICATE-----"
        headers = {"X-SSL-Client-Cert": test_cert}
        
        cert_pem = await MutualTLSHandler.extract_client_certificate(headers)
        assert cert_pem == test_cert
    
    def test_enrollment_token_validation(self, cert_manager):
        """Test enrollment token validation."""
        user_id = uuid4()
        device_id = uuid4()
        
        # Test with wrong user
        token_data = {
            "user_id": str(uuid4()),  # Different user
            "device_id": str(device_id),
            "expires_at": (datetime.utcnow() + timedelta(hours=1)).isoformat(),
            "nonce": "test-nonce"
        }
        
        import json
        import base64
        token = base64.urlsafe_b64encode(
            json.dumps(token_data).encode()
        ).decode()
        
        is_valid = cert_manager._validate_enrollment_token(token, user_id, device_id)
        assert is_valid is False
        
        # Test with correct user and device
        token_data["user_id"] = str(user_id)
        token = base64.urlsafe_b64encode(
            json.dumps(token_data).encode()
        ).decode()
        
        is_valid = cert_manager._validate_enrollment_token(token, user_id, device_id)
        assert is_valid is True
    
    def test_trusted_issuer_checking(self, cert_manager):
        """Test trusted issuer validation."""
        # Configure trusted issuers
        cert_manager.trusted_issuers = ["CN=Test CA"]
        
        # Should accept trusted issuer
        assert cert_manager._is_trusted_issuer("CN=Test CA, O=Example") is True
        
        # Should reject untrusted issuer
        assert cert_manager._is_trusted_issuer("CN=Evil CA, O=Malicious") is False
    
    def test_certificate_chain_extraction(self, cert_manager, test_certificate, ca_certificate):
        """Test certificate chain extraction."""
        # Create a chain with device cert + CA cert
        chain_pem = test_certificate["certificate"] + "\n" + ca_certificate
        
        ca_cert = cert_manager._extract_ca_from_chain(chain_pem)
        
        # Should extract the CA certificate (last in chain)
        assert ca_cert is not None
        assert "Test Root CA" in ca_cert