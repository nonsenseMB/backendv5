"""
Unit tests for Credential Validator.
Tests WebAuthn credential validation and signature verification.
"""

import base64
from unittest.mock import Mock, patch

import pytest
import cbor2
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from src.infrastructure.auth.credential_validator import CredentialValidator


class TestCredentialValidator:
    """Test credential validation functionality."""

    def test_cose_algorithm_constants(self):
        """Test COSE algorithm constants are correctly defined."""
        assert CredentialValidator.COSE_ALG_ES256 == -7
        assert CredentialValidator.COSE_ALG_ES384 == -35
        assert CredentialValidator.COSE_ALG_ES512 == -36
        assert CredentialValidator.COSE_ALG_RS256 == -257
        assert CredentialValidator.COSE_ALG_RS384 == -258
        assert CredentialValidator.COSE_ALG_RS512 == -259
        assert CredentialValidator.COSE_ALG_PS256 == -37
        assert CredentialValidator.COSE_ALG_PS384 == -38
        assert CredentialValidator.COSE_ALG_PS512 == -39

    def test_cose_key_type_constants(self):
        """Test COSE key type constants are correctly defined."""
        assert CredentialValidator.COSE_KTY_EC2 == 2
        assert CredentialValidator.COSE_KTY_RSA == 3

    def test_cose_curve_constants(self):
        """Test COSE curve constants are correctly defined."""
        assert CredentialValidator.COSE_CRV_P256 == 1
        assert CredentialValidator.COSE_CRV_P384 == 2
        assert CredentialValidator.COSE_CRV_P521 == 3


class TestAttestationObjectParsing:
    """Test attestation object parsing."""

    def test_parse_attestation_object_none_format(self):
        """Test parsing attestation object with 'none' format."""
        # Create a minimal attestation object
        auth_data = bytearray(37)
        auth_data[32] = 0x41  # Flags: UP=1, AT=1
        auth_data[33:37] = (0).to_bytes(4, 'big')  # Sign count = 0

        attestation_obj = {
            "fmt": "none",
            "authData": bytes(auth_data),
            "attStmt": {}
        }

        cbor_data = cbor2.dumps(attestation_obj)

        result = CredentialValidator.parse_attestation_object(cbor_data)

        assert result["fmt"] == "none"
        assert result["authData"] == bytes(auth_data)
        assert result["attStmt"] == {}
        assert "parsedAuthData" in result

    def test_parse_attestation_object_packed_format(self):
        """Test parsing attestation object with 'packed' format."""
        auth_data = bytearray(37)
        auth_data[32] = 0x41  # Flags: UP=1, AT=1

        attestation_obj = {
            "fmt": "packed",
            "authData": bytes(auth_data),
            "attStmt": {
                "alg": -7,
                "sig": b"mock_signature"
            }
        }

        cbor_data = cbor2.dumps(attestation_obj)

        result = CredentialValidator.parse_attestation_object(cbor_data)

        assert result["fmt"] == "packed"
        assert result["attStmt"]["alg"] == -7
        assert result["attStmt"]["sig"] == b"mock_signature"

    def test_parse_attestation_object_invalid_cbor(self):
        """Test parsing invalid CBOR data."""
        invalid_cbor = b"invalid_cbor_data"

        with pytest.raises(ValueError, match="Invalid attestation object"):
            CredentialValidator.parse_attestation_object(invalid_cbor)

    def test_parse_attestation_object_missing_fields(self):
        """Test parsing attestation object with missing required fields."""
        # Missing authData
        incomplete_obj = {
            "fmt": "none",
            "attStmt": {}
        }

        cbor_data = cbor2.dumps(incomplete_obj)

        result = CredentialValidator.parse_attestation_object(cbor_data)

        # Should handle missing authData gracefully
        assert result["fmt"] == "none"
        assert result["authData"] == b""


class TestAuthenticatorDataParsing:
    """Test authenticator data parsing."""

    def test_parse_authenticator_data_minimal(self):
        """Test parsing minimal authenticator data (37 bytes)."""
        auth_data = bytearray(37)
        # RP ID hash (32 bytes) - all zeros
        # Flags (1 byte)
        auth_data[32] = 0x01  # UP=1
        # Sign count (4 bytes)
        auth_data[33:37] = (42).to_bytes(4, 'big')

        result = CredentialValidator.parse_authenticator_data(bytes(auth_data))

        assert len(result["rpIdHash"]) == 32
        assert result["flags"]["up"] is True
        assert result["flags"]["uv"] is False
        assert result["flags"]["at"] is False
        assert result["flags"]["ed"] is False
        assert result["signCount"] == 42

    def test_parse_authenticator_data_with_attested_credential(self):
        """Test parsing authenticator data with attested credential data."""
        # Create auth data with attested credential data flag
        auth_data = bytearray(37)
        auth_data[32] = 0x41  # UP=1, AT=1

        # Add AAGUID (16 bytes)
        aaguid = b'\x12\x34\x56\x78' * 4
        auth_data.extend(aaguid)

        # Add credential ID length (2 bytes)
        cred_id = b"test_credential_id"
        auth_data.extend(len(cred_id).to_bytes(2, 'big'))

        # Add credential ID
        auth_data.extend(cred_id)

        # Add credential public key (CBOR encoded)
        public_key = {"1": 2, "3": -7, "-1": 1, "-2": b"x_coord", "-3": b"y_coord"}
        public_key_cbor = cbor2.dumps(public_key)
        auth_data.extend(public_key_cbor)

        result = CredentialValidator.parse_authenticator_data(bytes(auth_data))

        assert result["flags"]["at"] is True
        assert result["aaguid"] == aaguid
        assert result["credentialId"] == cred_id
        assert result["credentialPublicKey"] == public_key

    def test_parse_authenticator_data_invalid_cbor_in_public_key(self):
        """Test parsing authenticator data with invalid CBOR in public key."""
        auth_data = bytearray(37)
        auth_data[32] = 0x41  # UP=1, AT=1

        # Add AAGUID (16 bytes)
        aaguid = b'\x12\x34\x56\x78' * 4
        auth_data.extend(aaguid)

        # Add credential ID
        cred_id = b"test_cred"
        auth_data.extend(len(cred_id).to_bytes(2, 'big'))
        auth_data.extend(cred_id)

        # Add invalid CBOR public key
        auth_data.extend(b"invalid_cbor_data")

        result = CredentialValidator.parse_authenticator_data(bytes(auth_data))

        # Should store raw bytes when CBOR parsing fails
        assert result["credentialPublicKey"] == b"invalid_cbor_data"

    def test_parse_authenticator_data_too_short(self):
        """Test parsing authenticator data that's too short."""
        short_data = b"too_short"

        with pytest.raises(ValueError, match="Authenticator data too short"):
            CredentialValidator.parse_authenticator_data(short_data)

    def test_parse_authenticator_data_flags_parsing(self):
        """Test parsing of all authenticator data flags."""
        auth_data = bytearray(37)
        # Set all flags
        auth_data[32] = 0xC5  # UP=1, UV=1, AT=1, ED=1

        result = CredentialValidator.parse_authenticator_data(bytes(auth_data))

        assert result["flags"]["up"] is True   # User present
        assert result["flags"]["uv"] is True   # User verified
        assert result["flags"]["at"] is True   # Attested credential data
        assert result["flags"]["ed"] is True   # Extension data


class TestSignatureVerification:
    """Test signature verification functionality."""

    def test_verify_signature_unsupported_key_type(self):
        """Test signature verification with unsupported key type."""
        public_key = {
            1: 999,  # Unsupported key type
            3: -7    # Algorithm
        }
        signature = b"test_signature"
        auth_data = b"test_auth_data"
        client_data_hash = b"test_hash"

        result = CredentialValidator.verify_signature(
            public_key, signature, auth_data, client_data_hash
        )

        assert result is False

    def test_verify_signature_missing_key_type(self):
        """Test signature verification with missing key type."""
        public_key = {
            3: -7  # Algorithm but no key type
        }
        signature = b"test_signature"
        auth_data = b"test_auth_data"
        client_data_hash = b"test_hash"

        result = CredentialValidator.verify_signature(
            public_key, signature, auth_data, client_data_hash
        )

        assert result is False

    @patch('src.infrastructure.auth.credential_validator.CredentialValidator._verify_ec_signature')
    def test_verify_signature_ec_key(self, mock_verify_ec):
        """Test signature verification with EC key."""
        mock_verify_ec.return_value = True

        public_key = {
            1: CredentialValidator.COSE_KTY_EC2,  # EC key type
            3: CredentialValidator.COSE_ALG_ES256  # ES256 algorithm
        }
        signature = b"test_signature"
        auth_data = b"test_auth_data"
        client_data_hash = b"test_hash"

        result = CredentialValidator.verify_signature(
            public_key, signature, auth_data, client_data_hash
        )

        assert result is True
        mock_verify_ec.assert_called_once()

    @patch('src.infrastructure.auth.credential_validator.CredentialValidator._verify_rsa_signature')
    def test_verify_signature_rsa_key(self, mock_verify_rsa):
        """Test signature verification with RSA key."""
        mock_verify_rsa.return_value = True

        public_key = {
            1: CredentialValidator.COSE_KTY_RSA,  # RSA key type
            3: CredentialValidator.COSE_ALG_RS256  # RS256 algorithm
        }
        signature = b"test_signature"
        auth_data = b"test_auth_data"
        client_data_hash = b"test_hash"

        result = CredentialValidator.verify_signature(
            public_key, signature, auth_data, client_data_hash
        )

        assert result is True
        mock_verify_rsa.assert_called_once()

    def test_verify_signature_exception_handling(self):
        """Test signature verification exception handling."""
        public_key = {
            1: CredentialValidator.COSE_KTY_EC2,
            3: CredentialValidator.COSE_ALG_ES256
        }

        # Use None to trigger exception
        result = CredentialValidator.verify_signature(
            public_key, None, b"auth_data", b"hash"
        )

        assert result is False


class TestECSignatureVerification:
    """Test EC signature verification."""

    def test_verify_ec_signature_missing_coordinates(self):
        """Test EC signature verification with missing coordinates."""
        public_key = {
            -1: CredentialValidator.COSE_CRV_P256,  # Curve
            # Missing -2 (x) and -3 (y)
        }
        signature = b"test_signature"
        data = b"test_data"
        algorithm = CredentialValidator.COSE_ALG_ES256

        result = CredentialValidator._verify_ec_signature(
            public_key, signature, data, algorithm
        )

        assert result is False

    def test_verify_ec_signature_unsupported_curve(self):
        """Test EC signature verification with unsupported curve."""
        public_key = {
            -1: 999,  # Unsupported curve
            -2: b"x_coordinate",
            -3: b"y_coordinate"
        }
        signature = b"test_signature"
        data = b"test_data"
        algorithm = CredentialValidator.COSE_ALG_ES256

        result = CredentialValidator._verify_ec_signature(
            public_key, signature, data, algorithm
        )

        assert result is False

    @patch('cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers.public_key')
    def test_verify_ec_signature_p256_success(self, mock_public_key):
        """Test successful EC signature verification with P-256."""
        # Setup mock
        mock_key = Mock()
        mock_public_key.return_value = mock_key

        public_key = {
            -1: CredentialValidator.COSE_CRV_P256,
            -2: (32).to_bytes(32, 'big'),  # x coordinate
            -3: (64).to_bytes(32, 'big')   # y coordinate
        }
        signature = b"test_signature"
        data = b"test_data"
        algorithm = CredentialValidator.COSE_ALG_ES256

        result = CredentialValidator._verify_ec_signature(
            public_key, signature, data, algorithm
        )

        assert result is True
        mock_key.verify.assert_called_once()

    @patch('cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers.public_key')
    def test_verify_ec_signature_invalid_signature(self, mock_public_key):
        """Test EC signature verification with invalid signature."""
        mock_key = Mock()
        mock_key.verify.side_effect = InvalidSignature("Invalid signature")
        mock_public_key.return_value = mock_key

        public_key = {
            -1: CredentialValidator.COSE_CRV_P256,
            -2: (32).to_bytes(32, 'big'),
            -3: (64).to_bytes(32, 'big')
        }
        signature = b"invalid_signature"
        data = b"test_data"
        algorithm = CredentialValidator.COSE_ALG_ES256

        result = CredentialValidator._verify_ec_signature(
            public_key, signature, data, algorithm
        )

        assert result is False

    def test_verify_ec_signature_p384_curve(self):
        """Test EC signature verification with P-384 curve."""
        public_key = {
            -1: CredentialValidator.COSE_CRV_P384,
            -2: (32).to_bytes(48, 'big'),  # 48 bytes for P-384
            -3: (64).to_bytes(48, 'big')
        }

        with patch('cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers.public_key') as mock_pk:
            mock_key = Mock()
            mock_pk.return_value = mock_key

            result = CredentialValidator._verify_ec_signature(
                public_key, b"sig", b"data", CredentialValidator.COSE_ALG_ES384
            )

            # Should use SECP384R1 curve and SHA384
            mock_pk.assert_called_once()
            args = mock_pk.call_args[0]
            assert isinstance(args[2], ec.SECP384R1)

    def test_verify_ec_signature_p521_curve(self):
        """Test EC signature verification with P-521 curve."""
        public_key = {
            -1: CredentialValidator.COSE_CRV_P521,
            -2: (32).to_bytes(66, 'big'),  # 66 bytes for P-521
            -3: (64).to_bytes(66, 'big')
        }

        with patch('cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers.public_key') as mock_pk:
            mock_key = Mock()
            mock_pk.return_value = mock_key

            CredentialValidator._verify_ec_signature(
                public_key, b"sig", b"data", CredentialValidator.COSE_ALG_ES512
            )

            # Should use SECP521R1 curve
            mock_pk.assert_called_once()
            args = mock_pk.call_args[0]
            assert isinstance(args[2], ec.SECP521R1)


class TestRSASignatureVerification:
    """Test RSA signature verification."""

    def test_verify_rsa_signature_missing_parameters(self):
        """Test RSA signature verification with missing parameters."""
        public_key = {
            -1: b"modulus",
            # Missing -2 (exponent)
        }
        signature = b"test_signature"
        data = b"test_data"
        algorithm = CredentialValidator.COSE_ALG_RS256

        result = CredentialValidator._verify_rsa_signature(
            public_key, signature, data, algorithm
        )

        assert result is False

    def test_verify_rsa_signature_unsupported_algorithm(self):
        """Test RSA signature verification with unsupported algorithm."""
        public_key = {
            -1: (12345).to_bytes(256, 'big'),  # Modulus
            -2: (65537).to_bytes(3, 'big')     # Exponent
        }
        signature = b"test_signature"
        data = b"test_data"
        algorithm = -999  # Unsupported algorithm

        result = CredentialValidator._verify_rsa_signature(
            public_key, signature, data, algorithm
        )

        assert result is False

    @patch('cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers.public_key')
    def test_verify_rsa_signature_rs256_success(self, mock_public_key):
        """Test successful RSA signature verification with RS256."""
        mock_key = Mock()
        mock_public_key.return_value = mock_key

        public_key = {
            -1: (12345).to_bytes(256, 'big'),  # Modulus
            -2: (65537).to_bytes(3, 'big')     # Exponent
        }
        signature = b"test_signature"
        data = b"test_data"
        algorithm = CredentialValidator.COSE_ALG_RS256

        result = CredentialValidator._verify_rsa_signature(
            public_key, signature, data, algorithm
        )

        assert result is True
        mock_key.verify.assert_called_once()

    @patch('cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers.public_key')
    def test_verify_rsa_signature_ps256_success(self, mock_public_key):
        """Test successful RSA signature verification with PS256 (PSS padding)."""
        mock_key = Mock()
        mock_public_key.return_value = mock_key

        public_key = {
            -1: (12345).to_bytes(256, 'big'),
            -2: (65537).to_bytes(3, 'big')
        }
        signature = b"test_signature"
        data = b"test_data"
        algorithm = CredentialValidator.COSE_ALG_PS256

        result = CredentialValidator._verify_rsa_signature(
            public_key, signature, data, algorithm
        )

        assert result is True
        # Verify PSS padding was used
        mock_key.verify.assert_called_once()

    @patch('cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers.public_key')
    def test_verify_rsa_signature_invalid_signature(self, mock_public_key):
        """Test RSA signature verification with invalid signature."""
        mock_key = Mock()
        mock_key.verify.side_effect = InvalidSignature("Invalid signature")
        mock_public_key.return_value = mock_key

        public_key = {
            -1: (12345).to_bytes(256, 'big'),
            -2: (65537).to_bytes(3, 'big')
        }
        signature = b"invalid_signature"
        data = b"test_data"
        algorithm = CredentialValidator.COSE_ALG_RS256

        result = CredentialValidator._verify_rsa_signature(
            public_key, signature, data, algorithm
        )

        assert result is False


class TestAttestationVerification:
    """Test attestation verification."""

    def test_verify_attestation_none_format(self):
        """Test verification of 'none' attestation format."""
        result = CredentialValidator.verify_attestation(
            fmt="none",
            att_stmt={},
            auth_data=b"test_auth_data",
            client_data_hash=b"test_hash"
        )

        assert result == (True, "none")

    def test_verify_attestation_unsupported_format(self):
        """Test verification of unsupported attestation format."""
        result = CredentialValidator.verify_attestation(
            fmt="unsupported",
            att_stmt={},
            auth_data=b"test_auth_data",
            client_data_hash=b"test_hash"
        )

        assert result == (False, None)

    @patch('src.infrastructure.auth.credential_validator.CredentialValidator._verify_packed_attestation')
    def test_verify_attestation_packed_format(self, mock_verify_packed):
        """Test verification of 'packed' attestation format."""
        mock_verify_packed.return_value = (True, "direct")

        result = CredentialValidator.verify_attestation(
            fmt="packed",
            att_stmt={"alg": -7, "sig": b"signature"},
            auth_data=b"test_auth_data",
            client_data_hash=b"test_hash"
        )

        assert result == (True, "direct")
        mock_verify_packed.assert_called_once()

    @patch('src.infrastructure.auth.credential_validator.CredentialValidator._verify_u2f_attestation')
    def test_verify_attestation_u2f_format(self, mock_verify_u2f):
        """Test verification of 'fido-u2f' attestation format."""
        mock_verify_u2f.return_value = (True, "direct")

        result = CredentialValidator.verify_attestation(
            fmt="fido-u2f",
            att_stmt={"sig": b"signature", "x5c": [b"cert"]},
            auth_data=b"test_auth_data",
            client_data_hash=b"test_hash"
        )

        assert result == (True, "direct")
        mock_verify_u2f.assert_called_once()


class TestPackedAttestationVerification:
    """Test packed attestation verification."""

    def test_verify_packed_attestation_missing_signature(self):
        """Test packed attestation verification with missing signature."""
        att_stmt = {"alg": -7}  # No signature

        result = CredentialValidator._verify_packed_attestation(
            att_stmt=att_stmt,
            auth_data=b"test_auth_data",
            client_data_hash=b"test_hash"
        )

        assert result == (False, None)

    @patch('cryptography.x509.load_der_x509_certificate')
    @patch('cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.verify')
    def test_verify_packed_attestation_with_certificate_ec(self, mock_verify, mock_load_cert):
        """Test packed attestation verification with EC certificate."""
        # Setup mock certificate with EC public key
        mock_cert = Mock()
        mock_ec_key = Mock(spec=ec.EllipticCurvePublicKey)
        mock_cert.public_key.return_value = mock_ec_key
        mock_load_cert.return_value = mock_cert

        att_stmt = {
            "alg": -7,
            "sig": b"test_signature",
            "x5c": [b"der_certificate"]
        }

        result = CredentialValidator._verify_packed_attestation(
            att_stmt=att_stmt,
            auth_data=b"test_auth_data",
            client_data_hash=b"test_hash"
        )

        assert result == (True, "direct")
        mock_verify.assert_called_once()

    @patch('cryptography.x509.load_der_x509_certificate')
    @patch('cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.verify')
    def test_verify_packed_attestation_with_certificate_rsa(self, mock_verify, mock_load_cert):
        """Test packed attestation verification with RSA certificate."""
        # Setup mock certificate with RSA public key
        mock_cert = Mock()
        mock_rsa_key = Mock(spec=rsa.RSAPublicKey)
        mock_cert.public_key.return_value = mock_rsa_key
        mock_load_cert.return_value = mock_cert

        att_stmt = {
            "alg": -257,  # RS256
            "sig": b"test_signature",
            "x5c": [b"der_certificate"]
        }

        result = CredentialValidator._verify_packed_attestation(
            att_stmt=att_stmt,
            auth_data=b"test_auth_data",
            client_data_hash=b"test_hash"
        )

        assert result == (True, "direct")
        mock_verify.assert_called_once()

    @patch('cryptography.x509.load_der_x509_certificate')
    @patch('cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.verify')
    def test_verify_packed_attestation_invalid_signature(self, mock_verify, mock_load_cert):
        """Test packed attestation verification with invalid signature."""
        mock_verify.side_effect = InvalidSignature("Invalid signature")
        mock_cert = Mock()
        mock_ec_key = Mock(spec=ec.EllipticCurvePublicKey)
        mock_cert.public_key.return_value = mock_ec_key
        mock_load_cert.return_value = mock_cert

        att_stmt = {
            "alg": -7,
            "sig": b"invalid_signature",
            "x5c": [b"der_certificate"]
        }

        result = CredentialValidator._verify_packed_attestation(
            att_stmt=att_stmt,
            auth_data=b"test_auth_data",
            client_data_hash=b"test_hash"
        )

        assert result == (False, None)

    @patch('src.infrastructure.auth.credential_validator.CredentialValidator.parse_authenticator_data')
    def test_verify_packed_attestation_self_attestation(self, mock_parse_auth):
        """Test packed attestation verification with self-attestation."""
        mock_parse_auth.return_value = {
            "credentialPublicKey": {"1": 2, "3": -7}
        }

        att_stmt = {
            "alg": -7,
            "sig": b"test_signature"
            # No x5c for self-attestation
        }

        result = CredentialValidator._verify_packed_attestation(
            att_stmt=att_stmt,
            auth_data=b"test_auth_data",
            client_data_hash=b"test_hash"
        )

        assert result == (True, "self")

    @patch('src.infrastructure.auth.credential_validator.CredentialValidator.parse_authenticator_data')
    def test_verify_packed_attestation_self_attestation_no_public_key(self, mock_parse_auth):
        """Test packed attestation verification with self-attestation but no public key."""
        mock_parse_auth.return_value = {}  # No credentialPublicKey

        att_stmt = {
            "alg": -7,
            "sig": b"test_signature"
        }

        result = CredentialValidator._verify_packed_attestation(
            att_stmt=att_stmt,
            auth_data=b"test_auth_data",
            client_data_hash=b"test_hash"
        )

        assert result == (False, None)


class TestU2FAttestationVerification:
    """Test FIDO U2F attestation verification."""

    def test_verify_u2f_attestation_success(self):
        """Test successful U2F attestation verification."""
        att_stmt = {
            "sig": b"test_signature",
            "x5c": [b"der_certificate"]
        }

        result = CredentialValidator._verify_u2f_attestation(
            att_stmt=att_stmt,
            auth_data=b"test_auth_data",
            client_data_hash=b"test_hash"
        )

        assert result == (True, "direct")

    def test_verify_u2f_attestation_missing_signature(self):
        """Test U2F attestation verification with missing signature."""
        att_stmt = {
            "x5c": [b"der_certificate"]
        }

        result = CredentialValidator._verify_u2f_attestation(
            att_stmt=att_stmt,
            auth_data=b"test_auth_data",
            client_data_hash=b"test_hash"
        )

        assert result == (False, None)

    def test_verify_u2f_attestation_missing_certificate(self):
        """Test U2F attestation verification with missing certificate."""
        att_stmt = {
            "sig": b"test_signature"
        }

        result = CredentialValidator._verify_u2f_attestation(
            att_stmt=att_stmt,
            auth_data=b"test_auth_data",
            client_data_hash=b"test_hash"
        )

        assert result == (False, None)


class TestPublicKeyExtraction:
    """Test public key extraction and encoding."""

    def test_extract_public_key_from_cose(self):
        """Test extracting public key from COSE format."""
        cose_key = {
            "1": 2,   # Key type: EC2
            "3": -7,  # Algorithm: ES256
            "-1": 1,  # Curve: P-256
            "-2": b"x_coordinate",
            "-3": b"y_coordinate"
        }

        result = CredentialValidator.extract_public_key_from_cose(cose_key)

        # Should return base64-encoded CBOR
        assert isinstance(result, str)
        assert len(result) > 0

        # Verify it can be decoded back
        decoded = CredentialValidator.decode_public_key(result)
        assert decoded == cose_key

    def test_extract_public_key_from_cose_exception(self):
        """Test public key extraction with invalid data."""
        # Create a key that can't be CBOR encoded
        class UnserializableObject:
            pass

        cose_key = {
            "1": UnserializableObject()  # Can't be serialized
        }

        with pytest.raises(Exception):
            CredentialValidator.extract_public_key_from_cose(cose_key)

    def test_decode_public_key_success(self):
        """Test successful public key decoding."""
        cose_key = {"1": 2, "3": -7}
        encoded = CredentialValidator.extract_public_key_from_cose(cose_key)

        result = CredentialValidator.decode_public_key(encoded)

        assert result == cose_key

    def test_decode_public_key_with_padding(self):
        """Test public key decoding with missing padding."""
        cose_key = {"1": 2, "3": -7}
        encoded = CredentialValidator.extract_public_key_from_cose(cose_key)
        
        # Remove padding
        encoded_no_padding = encoded.rstrip('=')

        result = CredentialValidator.decode_public_key(encoded_no_padding)

        assert result == cose_key

    def test_decode_public_key_invalid_base64(self):
        """Test public key decoding with invalid base64."""
        invalid_encoded = "not_valid_base64!"

        with pytest.raises(Exception):
            CredentialValidator.decode_public_key(invalid_encoded)

    def test_decode_public_key_invalid_cbor(self):
        """Test public key decoding with invalid CBOR."""
        # Create valid base64 but invalid CBOR
        invalid_cbor = base64.urlsafe_b64encode(b"not_cbor_data").decode('utf-8')

        with pytest.raises(Exception):
            CredentialValidator.decode_public_key(invalid_cbor)


class TestOtherAttestationFormats:
    """Test other attestation formats."""

    def test_verify_tpm_attestation(self):
        """Test TPM attestation verification."""
        result = CredentialValidator._verify_tpm_attestation(
            att_stmt={},
            auth_data=b"test_auth_data",
            client_data_hash=b"test_hash"
        )

        assert result == (True, "direct")

    def test_verify_android_key_attestation(self):
        """Test Android Key attestation verification."""
        result = CredentialValidator._verify_android_key_attestation(
            att_stmt={},
            auth_data=b"test_auth_data",
            client_data_hash=b"test_hash"
        )

        assert result == (True, "direct")

    def test_verify_safetynet_attestation(self):
        """Test Android SafetyNet attestation verification."""
        result = CredentialValidator._verify_safetynet_attestation(
            att_stmt={},
            auth_data=b"test_auth_data",
            client_data_hash=b"test_hash"
        )

        assert result == (True, "indirect")

    def test_verify_apple_attestation(self):
        """Test Apple attestation verification."""
        result = CredentialValidator._verify_apple_attestation(
            att_stmt={},
            auth_data=b"test_auth_data",
            client_data_hash=b"test_hash"
        )

        assert result == (True, "direct")