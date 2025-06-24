"""WebAuthn manager for device authentication."""
import base64
import hashlib
import secrets
from uuid import UUID

from src.api.v1.auth.schemas import (
    AuthenticationOptions,
    DeviceAuthenticationVerification,
    DeviceRegistrationOptions,
    DeviceRegistrationVerification,
)
from src.api.v1.auth.validators import WebAuthnValidator
from src.core.config import settings
from src.core.logging import get_logger
from src.infrastructure.auth.credential_validator import CredentialValidator

logger = get_logger(__name__)


class VerificationResult:
    """Result of WebAuthn verification."""

    def __init__(
        self,
        verified: bool,
        error: str | None = None,
        public_key: str | None = None,
        sign_count: int | None = None,
        new_sign_count: int | None = None,
        attestation_type: str | None = None,
        attestation_data: dict | None = None,
        aaguid: UUID | None = None
    ):
        """Initialize verification result."""
        self.verified = verified
        self.error = error
        self.public_key = public_key
        self.sign_count = sign_count
        self.new_sign_count = new_sign_count
        self.attestation_type = attestation_type
        self.attestation_data = attestation_data
        self.aaguid = aaguid


class WebAuthnManager:
    """Manager for WebAuthn operations."""

    def __init__(self):
        """Initialize WebAuthn manager."""
        self.rp_id = getattr(settings, "WEBAUTHN_RP_ID", settings.APP_DOMAIN)
        self.rp_name = getattr(settings, "WEBAUTHN_RP_NAME", settings.APP_NAME)
        self.rp_icon = getattr(settings, "WEBAUTHN_RP_ICON", None)
        self.user_verification = getattr(settings, "WEBAUTHN_USER_VERIFICATION", "required")
        self.attestation = getattr(settings, "WEBAUTHN_ATTESTATION", "direct")
        self.timeout = getattr(settings, "WEBAUTHN_TIMEOUT", 60000)
        self.allowed_origins = self._get_allowed_origins()

    def _get_allowed_origins(self) -> list[str]:
        """Get allowed origins for WebAuthn."""
        origins = []

        # Add configured CORS origins
        if hasattr(settings, "CORS_ORIGINS"):
            origins.extend([str(origin) for origin in settings.CORS_ORIGINS])

        # Add app domain with protocol
        if hasattr(settings, "APP_DOMAIN"):
            origins.append(f"https://{settings.APP_DOMAIN}")
            # Add localhost for development
            if settings.APP_ENV == "development":
                origins.append(f"http://{settings.APP_DOMAIN}")
                origins.append("http://localhost:3000")
                origins.append("http://localhost:8000")

        # Remove duplicates
        return list(set(origins))

    async def generate_registration_options(
        self,
        user_id: str,
        user_name: str,
        user_display_name: str,
        exclude_credentials: list[dict] = None
    ) -> DeviceRegistrationOptions:
        """
        Generate registration options for WebAuthn.
        
        Args:
            user_id: User identifier
            user_name: Username (email)
            user_display_name: Display name
            exclude_credentials: List of existing credentials to exclude
            
        Returns:
            Registration options
        """
        try:
            # Generate secure challenge
            challenge = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

            # Encode user ID
            user_id_encoded = base64.urlsafe_b64encode(user_id.encode('utf-8')).decode('utf-8').rstrip('=')

            # Build authenticator selection
            authenticator_selection = {
                "authenticatorAttachment": "platform",  # Prefer platform authenticators
                "residentKey": "preferred",
                "userVerification": self.user_verification
            }

            # Build registration options
            options = DeviceRegistrationOptions(
                challenge=challenge,
                rp_id=self.rp_id,
                rp_name=self.rp_name,
                user_id=user_id_encoded,
                user_name=user_name,
                user_display_name=user_display_name,
                attestation=self.attestation,
                authenticator_selection=authenticator_selection,
                timeout=self.timeout,
                exclude_credentials=exclude_credentials or []
            )

            logger.debug(
                "Generated registration options",
                user_id=user_id,
                rp_id=self.rp_id
            )

            return options

        except Exception as e:
            logger.error(
                "Failed to generate registration options",
                user_id=user_id,
                error=str(e),
                exc_info=True
            )
            raise

    async def verify_registration(
        self,
        credential: DeviceRegistrationVerification,
        challenge: str,
        user_id: str
    ) -> VerificationResult:
        """
        Verify registration response.
        
        Args:
            credential: Registration credential
            challenge: Expected challenge
            user_id: User identifier
            
        Returns:
            Verification result
        """
        try:
            # Validate client data
            client_data = WebAuthnValidator.validate_client_data_json(
                credential.response.client_data_json
            )

            # Verify type
            if client_data.get("type") != "webauthn.create":
                return VerificationResult(
                    verified=False,
                    error="Invalid client data type"
                )

            # Verify challenge
            if not WebAuthnValidator.validate_challenge(
                client_data.get("challenge"),
                challenge
            ):
                return VerificationResult(
                    verified=False,
                    error="Challenge mismatch"
                )

            # Verify origin
            if not WebAuthnValidator.validate_origin(
                client_data.get("origin"),
                self.allowed_origins
            ):
                return VerificationResult(
                    verified=False,
                    error="Invalid origin"
                )

            # Decode attestation object
            attestation_object = WebAuthnValidator.validate_base64(
                credential.response.attestation_object,
                "attestation_object"
            )

            # Parse attestation object
            attestation = CredentialValidator.parse_attestation_object(attestation_object)
            auth_data = attestation["authData"]
            parsed_auth = attestation["parsedAuthData"]

            # Verify attestation
            client_data_hash = hashlib.sha256(
                WebAuthnValidator.validate_base64(
                    credential.response.client_data_json,
                    "client_data_json"
                )
            ).digest()

            verified, attestation_type = CredentialValidator.verify_attestation(
                attestation["fmt"],
                attestation["attStmt"],
                auth_data,
                client_data_hash
            )

            if not verified:
                return VerificationResult(
                    verified=False,
                    error="Attestation verification failed"
                )

            # Extract public key
            if "credentialPublicKey" not in parsed_auth:
                return VerificationResult(
                    verified=False,
                    error="No public key in attestation"
                )

            public_key = CredentialValidator.extract_public_key_from_cose(
                parsed_auth["credentialPublicKey"]
            )

            # Extract AAGUID
            aaguid = None
            if "aaguid" in parsed_auth:
                aaguid_bytes = parsed_auth["aaguid"]
                if not all(b == 0 for b in aaguid_bytes):
                    import uuid
                    aaguid = uuid.UUID(bytes=aaguid_bytes)

            logger.info(
                "Registration verified",
                user_id=user_id,
                credential_id=credential.id[:20] + "...",
                aaguid=aaguid
            )

            return VerificationResult(
                verified=True,
                public_key=public_key,
                sign_count=parsed_auth.get("signCount", 0),
                attestation_type=attestation_type or "none",
                attestation_data={
                    "fmt": attestation["fmt"],
                    "aaguid": str(aaguid) if aaguid else None,
                    "flags": parsed_auth.get("flags", {})
                },
                aaguid=aaguid
            )

        except Exception as e:
            logger.error(
                "Registration verification failed",
                user_id=user_id,
                error=str(e),
                exc_info=True
            )
            return VerificationResult(
                verified=False,
                error=str(e)
            )

    async def generate_authentication_options(
        self,
        allow_credentials: list[dict]
    ) -> AuthenticationOptions:
        """
        Generate authentication options.
        
        Args:
            allow_credentials: List of allowed credentials
            
        Returns:
            Authentication options
        """
        try:
            # Generate secure challenge
            challenge = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

            # Build authentication options
            options = AuthenticationOptions(
                challenge=challenge,
                timeout=self.timeout,
                rp_id=self.rp_id,
                user_verification=self.user_verification,
                allow_credentials=allow_credentials
            )

            logger.debug(
                "Generated authentication options",
                credential_count=len(allow_credentials)
            )

            return options

        except Exception as e:
            logger.error(
                "Failed to generate authentication options",
                error=str(e),
                exc_info=True
            )
            raise

    async def verify_authentication(
        self,
        credential: DeviceAuthenticationVerification,
        challenge: str,
        public_key: str,
        sign_count: int
    ) -> VerificationResult:
        """
        Verify authentication response.
        
        Args:
            credential: Authentication credential
            challenge: Expected challenge
            public_key: Stored public key
            sign_count: Previous sign count
            
        Returns:
            Verification result
        """
        try:
            # Validate client data
            client_data = WebAuthnValidator.validate_client_data_json(
                credential.response.client_data_json
            )

            # Verify type
            if client_data.get("type") != "webauthn.get":
                return VerificationResult(
                    verified=False,
                    error="Invalid client data type"
                )

            # Verify challenge
            if not WebAuthnValidator.validate_challenge(
                client_data.get("challenge"),
                challenge
            ):
                return VerificationResult(
                    verified=False,
                    error="Challenge mismatch"
                )

            # Verify origin
            if not WebAuthnValidator.validate_origin(
                client_data.get("origin"),
                self.allowed_origins
            ):
                return VerificationResult(
                    verified=False,
                    error="Invalid origin"
                )

            # Decode authenticator data
            auth_data = base64.urlsafe_b64decode(
                credential.response.authenticator_data + "==="
            )

            # Verify user presence (simplified)
            if len(auth_data) < 37:
                return VerificationResult(
                    verified=False,
                    error="Invalid authenticator data"
                )

            # Extract flags and counter
            flags = auth_data[32]
            counter_bytes = auth_data[33:37]
            new_counter = int.from_bytes(counter_bytes, byteorder='big')

            # Verify user presence flag
            if not (flags & 0x01):
                return VerificationResult(
                    verified=False,
                    error="User presence not detected"
                )

            # Verify user verification if required
            if self.user_verification == "required" and not (flags & 0x04):
                return VerificationResult(
                    verified=False,
                    error="User verification required but not performed"
                )

            # Validate counter
            if not WebAuthnValidator.validate_counter(new_counter, sign_count):
                return VerificationResult(
                    verified=False,
                    error="Invalid counter - possible replay attack"
                )

            # Decode stored public key
            cose_key = CredentialValidator.decode_public_key(public_key)

            # Create client data hash
            client_data_hash = hashlib.sha256(
                WebAuthnValidator.validate_base64(
                    credential.response.client_data_json,
                    "client_data_json"
                )
            ).digest()

            # Decode signature
            signature = WebAuthnValidator.validate_base64(
                credential.response.signature,
                "signature"
            )

            # Verify signature
            signature_valid = CredentialValidator.verify_signature(
                cose_key,
                signature,
                auth_data,
                client_data_hash
            )

            if not signature_valid:
                return VerificationResult(
                    verified=False,
                    error="Signature verification failed"
                )

            logger.info(
                "Authentication verified",
                credential_id=credential.id[:20] + "...",
                new_counter=new_counter
            )

            return VerificationResult(
                verified=True,
                new_sign_count=new_counter
            )

        except Exception as e:
            logger.error(
                "Authentication verification failed",
                error=str(e),
                exc_info=True
            )
            return VerificationResult(
                verified=False,
                error=str(e)
            )

    def generate_device_name(self, user_agent: str) -> str:
        """
        Generate a device name from user agent.
        
        Args:
            user_agent: User agent string
            
        Returns:
            Device name
        """
        if not user_agent:
            return "Unknown Device"

        # Extract browser
        browser = self.extract_browser(user_agent)

        # Extract platform
        platform = self.extract_platform(user_agent)

        return f"{browser} on {platform}"

    def extract_browser(self, user_agent: str) -> str:
        """Extract browser from user agent."""
        if "Chrome" in user_agent and "Edg" not in user_agent:
            return "Chrome"
        elif "Firefox" in user_agent:
            return "Firefox"
        elif "Safari" in user_agent and "Chrome" not in user_agent:
            return "Safari"
        elif "Edg" in user_agent:
            return "Edge"
        else:
            return "Browser"

    def extract_platform(self, user_agent: str) -> str:
        """Extract platform from user agent."""
        if "Windows" in user_agent:
            return "Windows"
        elif "Macintosh" in user_agent:
            return "macOS"
        elif "Linux" in user_agent:
            return "Linux"
        elif "Android" in user_agent:
            return "Android"
        elif "iPhone" in user_agent or "iPad" in user_agent:
            return "iOS"
        else:
            return "Unknown"
