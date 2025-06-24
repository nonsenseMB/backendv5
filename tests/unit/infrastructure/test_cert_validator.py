"""Unit tests for certificate validator."""
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from src.infrastructure.auth.cert_validator import CertificateValidator


class TestCertificateValidator:
    """Test certificate validation functionality."""
    
    @pytest.fixture
    def sample_cert_pem(self):
        """Generate a sample certificate for testing."""
        # Generate key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Certificate details
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Corp"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test-device.example.com"),
        ])
        
        # Create certificate
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
                    x509.DNSName("test-device.example.com"),
                    x509.DNSName("*.test.example.com"),
                ]),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_agreement=False,
                    key_encipherment=False,
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
            .sign(private_key, hashes.SHA256(), default_backend())
        )
        
        # Convert to PEM
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        return cert_pem
    
    @pytest.fixture
    def expired_cert_pem(self):
        """Generate an expired certificate for testing."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "expired.example.com"),
        ])
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=400))
            .not_valid_after(datetime.now(timezone.utc) - timedelta(days=30))
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_agreement=False,
                    key_encipherment=False,
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
            .sign(private_key, hashes.SHA256(), default_backend())
        )
        
        return cert.public_bytes(serialization.Encoding.PEM).decode()
    
    def test_validate_certificate_success(self, sample_cert_pem):
        """Test successful certificate validation."""
        is_valid, cert_info, error = CertificateValidator.validate_certificate(
            cert_pem=sample_cert_pem,
            check_revocation=False  # Skip revocation for unit test
        )
        
        assert is_valid is True
        assert error is None
        assert "serial_number" in cert_info
        assert "fingerprint_sha256" in cert_info
        assert cert_info["common_name"] == "test-device.example.com"
        assert "test-device.example.com" in cert_info["san_dns_names"]
        assert "digital_signature" in cert_info["key_usage"]
        assert "1.3.6.1.5.5.7.3.2" in cert_info["extended_key_usage"]  # Client auth
    
    def test_validate_expired_certificate(self, expired_cert_pem):
        """Test validation of expired certificate."""
        is_valid, cert_info, error = CertificateValidator.validate_certificate(
            cert_pem=expired_cert_pem,
            check_revocation=False
        )
        
        assert is_valid is False
        assert "expired" in error.lower()
        assert "common_name" in cert_info
    
    def test_validate_certificate_with_required_cn(self, sample_cert_pem):
        """Test certificate validation with required CN."""
        # Should pass with correct CN
        is_valid, _, error = CertificateValidator.validate_certificate(
            cert_pem=sample_cert_pem,
            required_cn="test-device.example.com",
            check_revocation=False
        )
        assert is_valid is True
        
        # Should fail with wrong CN
        is_valid, _, error = CertificateValidator.validate_certificate(
            cert_pem=sample_cert_pem,
            required_cn="wrong.example.com",
            check_revocation=False
        )
        assert is_valid is False
        assert "does not match" in error
    
    def test_validate_certificate_wildcard_cn(self, sample_cert_pem):
        """Test certificate validation with wildcard CN."""
        is_valid, _, error = CertificateValidator.validate_certificate(
            cert_pem=sample_cert_pem,
            required_cn="*.example.com",
            check_revocation=False
        )
        # This should pass since test-device.example.com matches *.example.com
        assert is_valid is True
    
    def test_extract_cert_info(self, sample_cert_pem):
        """Test certificate information extraction."""
        cert = x509.load_pem_x509_certificate(
            sample_cert_pem.encode(),
            default_backend()
        )
        
        cert_info = CertificateValidator._extract_cert_info(cert)
        
        assert cert_info["common_name"] == "test-device.example.com"
        assert cert_info["key_algorithm"] == "RSA"
        assert cert_info["key_size"] == 2048
        assert "test-device.example.com" in cert_info["san_dns_names"]
        assert "*.test.example.com" in cert_info["san_dns_names"]
        assert "digital_signature" in cert_info["key_usage"]
        assert "1.3.6.1.5.5.7.3.2" in cert_info["extended_key_usage"]
    
    def test_validate_basic_certificate_properties(self, sample_cert_pem):
        """Test basic certificate validation."""
        cert = x509.load_pem_x509_certificate(
            sample_cert_pem.encode(),
            default_backend()
        )
        
        is_valid, error = CertificateValidator._validate_basic(cert)
        
        # Should fail because it's self-signed (issuer == subject)
        assert is_valid is False
        assert "self-signed" in error.lower()
    
    def test_validate_dates(self, sample_cert_pem, expired_cert_pem):
        """Test certificate date validation."""
        # Valid certificate
        cert = x509.load_pem_x509_certificate(
            sample_cert_pem.encode(),
            default_backend()
        )
        is_valid, error = CertificateValidator._validate_dates(cert)
        assert is_valid is True
        
        # Expired certificate
        expired_cert = x509.load_pem_x509_certificate(
            expired_cert_pem.encode(),
            default_backend()
        )
        is_valid, error = CertificateValidator._validate_dates(expired_cert)
        assert is_valid is False
        assert "expired" in error.lower()
    
    def test_validate_key_strength(self, sample_cert_pem):
        """Test key strength validation."""
        cert = x509.load_pem_x509_certificate(
            sample_cert_pem.encode(),
            default_backend()
        )
        
        is_valid, error = CertificateValidator._validate_key_strength(cert)
        assert is_valid is True  # 2048-bit RSA should be valid
    
    def test_validate_key_usage(self, sample_cert_pem):
        """Test key usage validation."""
        cert = x509.load_pem_x509_certificate(
            sample_cert_pem.encode(),
            default_backend()
        )
        
        is_valid, error = CertificateValidator._validate_key_usage(cert)
        assert is_valid is True  # Should have digital signature and client auth
    
    def test_invalid_certificate_format(self):
        """Test validation with invalid certificate format."""
        invalid_cert = "-----BEGIN CERTIFICATE-----\nInvalid data\n-----END CERTIFICATE-----"
        
        is_valid, cert_info, error = CertificateValidator.validate_certificate(
            cert_pem=invalid_cert,
            check_revocation=False
        )
        
        assert is_valid is False
        assert "error" in error.lower()
        assert cert_info == {}
    
    @patch('httpx.Client')
    def test_check_crl_revoked(self, mock_client_class):
        """Test CRL checking for revoked certificate."""
        # Mock CRL response
        mock_client = Mock()
        mock_response = Mock()
        mock_response.content = b"mock_crl_data"
        mock_response.raise_for_status.return_value = None
        mock_client.get.return_value = mock_response
        mock_client.__enter__.return_value = mock_client
        mock_client.__exit__.return_value = None
        mock_client_class.return_value = mock_client
        
        # Mock CRL parsing
        with patch('cryptography.x509.load_der_x509_crl') as mock_load_crl:
            mock_crl = Mock()
            mock_revoked_cert = Mock()
            mock_crl.get_revoked_certificate_by_serial_number.return_value = mock_revoked_cert
            mock_load_crl.return_value = mock_crl
            
            # Mock certificate
            mock_cert = Mock()
            mock_cert.serial_number = 12345
            
            is_revoked, reason = CertificateValidator._check_crl(
                mock_cert,
                ["http://example.com/crl"]
            )
            
            assert is_revoked is True
    
    def test_generate_certificate_info_for_trust(self):
        """Test generating trust information from certificate."""
        cert_info = {
            "trust_chain_verified": True,
            "key_algorithm": "RSA",
            "key_size": 2048,
            "not_after": datetime.utcnow() + timedelta(days=365),
            "not_before": datetime.utcnow() - timedelta(days=1)
        }
        
        trust_info = CertificateValidator.generate_certificate_info_for_trust(cert_info)
        
        assert trust_info["has_valid_chain"] is True
        assert trust_info["key_algorithm"] == "RSA"
        assert trust_info["key_size"] == 2048
        assert trust_info["days_valid"] == 366  # Approximately
        assert "is_ev_cert" in trust_info
        assert "has_ct_logs" in trust_info