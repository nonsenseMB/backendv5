"""Validators for WebAuthn and device authentication."""
import base64
import json

from src.core.logging import get_logger

logger = get_logger(__name__)


class WebAuthnValidator:
    """Validator for WebAuthn data formats and values."""

    @staticmethod
    def validate_base64(data: str, field_name: str) -> bytes:
        """
        Validate and decode base64 data.
        
        Args:
            data: Base64 encoded string
            field_name: Name of the field for error messages
            
        Returns:
            Decoded bytes
            
        Raises:
            ValueError: If data is not valid base64
        """
        try:
            # Handle both standard and URL-safe base64
            # Add padding if missing
            padding = 4 - (len(data) % 4)
            if padding != 4:
                data += "=" * padding

            # Try URL-safe first, then standard
            try:
                return base64.urlsafe_b64decode(data)
            except Exception:
                return base64.b64decode(data)
        except Exception as e:
            raise ValueError(f"Invalid base64 in {field_name}: {str(e)}")

    @staticmethod
    def validate_client_data_json(client_data_json: str) -> dict:
        """
        Validate and parse client data JSON.
        
        Args:
            client_data_json: Base64 encoded client data
            
        Returns:
            Parsed client data dictionary
            
        Raises:
            ValueError: If client data is invalid
        """
        try:
            # Decode base64
            client_data_bytes = WebAuthnValidator.validate_base64(
                client_data_json, "client_data_json"
            )

            # Parse JSON
            client_data = json.loads(client_data_bytes.decode('utf-8'))

            # Validate required fields
            required_fields = ["type", "challenge", "origin"]
            for field in required_fields:
                if field not in client_data:
                    raise ValueError(f"Missing required field in client data: {field}")

            return client_data

        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in client data: {str(e)}")
        except Exception as e:
            raise ValueError(f"Invalid client data: {str(e)}")

    @staticmethod
    def validate_origin(origin: str, expected_origins: list[str]) -> bool:
        """
        Validate the origin from client data.
        
        Args:
            origin: Origin from client data
            expected_origins: List of allowed origins
            
        Returns:
            True if origin is valid
        """
        # Normalize origins (remove trailing slashes)
        origin = origin.rstrip("/")
        expected_origins = [o.rstrip("/") for o in expected_origins]

        return origin in expected_origins

    @staticmethod
    def validate_challenge(challenge: str, expected_challenge: str) -> bool:
        """
        Validate the challenge from client data.
        
        Args:
            challenge: Challenge from client data (base64)
            expected_challenge: Expected challenge (base64)
            
        Returns:
            True if challenges match
        """
        try:
            # Decode both challenges
            challenge_bytes = WebAuthnValidator.validate_base64(challenge, "challenge")
            expected_bytes = WebAuthnValidator.validate_base64(expected_challenge, "expected_challenge")

            # Compare as bytes
            return challenge_bytes == expected_bytes
        except Exception:
            return False

    @staticmethod
    def validate_credential_id(credential_id: str, max_length: int = 1023) -> bool:
        """
        Validate credential ID format and length.
        
        Args:
            credential_id: Base64 encoded credential ID
            max_length: Maximum allowed length after decoding
            
        Returns:
            True if credential ID is valid
        """
        try:
            # Decode and check length
            credential_bytes = WebAuthnValidator.validate_base64(
                credential_id, "credential_id"
            )

            if len(credential_bytes) > max_length:
                logger.warning(
                    "Credential ID too long",
                    length=len(credential_bytes),
                    max_length=max_length
                )
                return False

            # Credential ID should not be empty
            if len(credential_bytes) == 0:
                return False

            return True

        except Exception:
            return False

    @staticmethod
    def validate_user_verification(
        authenticator_data: bytes,
        requirement: str = "required"
    ) -> bool:
        """
        Validate user verification in authenticator data.
        
        Args:
            authenticator_data: Raw authenticator data bytes
            requirement: User verification requirement ("required", "preferred", "discouraged")
            
        Returns:
            True if user verification meets requirements
        """
        if len(authenticator_data) < 37:
            return False

        # Get flags byte (32nd byte)
        flags = authenticator_data[32]

        # User Verified (UV) flag is bit 2 (0x04)
        user_verified = bool(flags & 0x04)

        if requirement == "required":
            return user_verified
        elif requirement == "preferred":
            # For preferred, we accept either verified or not
            return True
        elif requirement == "discouraged":
            # For discouraged, we still accept if provided
            return True
        else:
            # Unknown requirement
            return False

    @staticmethod
    def validate_rp_id(rp_id: str) -> bool:
        """
        Validate Relying Party ID format.
        
        Args:
            rp_id: Relying Party identifier
            
        Returns:
            True if RP ID is valid
        """
        # RP ID should be a valid domain
        if not rp_id:
            return False

        # Basic domain validation
        # Should not contain protocol or path
        if "://" in rp_id or "/" in rp_id:
            return False

        # Should contain at least one dot for valid domain
        # (except for localhost which is special case)
        if rp_id == "localhost":
            return True

        if "." not in rp_id:
            return False

        # Basic length check
        if len(rp_id) > 253:  # Max domain length
            return False

        return True

    @staticmethod
    def validate_counter(
        new_counter: int,
        stored_counter: int,
        allow_zero: bool = False
    ) -> bool:
        """
        Validate signature counter for replay protection.
        
        Args:
            new_counter: Counter from authentication
            stored_counter: Previously stored counter
            allow_zero: Whether to allow zero counters (some authenticators don't increment)
            
        Returns:
            True if counter is valid
        """
        # If authenticator doesn't implement counter (always 0)
        if new_counter == 0 and stored_counter == 0 and allow_zero:
            return True

        # Counter must be greater than stored counter
        if new_counter > stored_counter:
            return True

        # Log potential replay attack
        logger.warning(
            "Counter validation failed - potential replay attack",
            new_counter=new_counter,
            stored_counter=stored_counter
        )

        return False

    @staticmethod
    def extract_aaguid(attestation_object: bytes) -> str | None:
        """
        Extract AAGUID from attestation object.
        
        Args:
            attestation_object: CBOR encoded attestation object
            
        Returns:
            AAGUID as string or None if not found
        """
        try:
            import cbor2

            # Decode CBOR
            attestation = cbor2.loads(attestation_object)

            # Get authenticator data
            auth_data = attestation.get("authData", b"")

            if len(auth_data) < 53:
                return None

            # AAGUID is bytes 37-53 (16 bytes)
            aaguid_bytes = auth_data[37:53]

            # Convert to UUID string
            if all(b == 0 for b in aaguid_bytes):
                # All zeros means no AAGUID
                return None

            # Format as UUID
            import uuid
            return str(uuid.UUID(bytes=aaguid_bytes))

        except Exception as e:
            logger.debug(
                "Failed to extract AAGUID",
                error=str(e)
            )
            return None

    @staticmethod
    def validate_attestation_type(attestation_type: str) -> bool:
        """
        Validate attestation type.
        
        Args:
            attestation_type: Type of attestation
            
        Returns:
            True if attestation type is valid
        """
        valid_types = [
            "none",
            "indirect",
            "direct",
            "enterprise"
        ]

        return attestation_type in valid_types
