"""Token exchange service for converting Authentik tokens to internal API tokens."""
from uuid import UUID

from pydantic import BaseModel, Field

from src.core.auth.jwt_manager import JWTManager
from src.core.logging import get_logger
from src.core.logging.audit import AuditEventType, AuditSeverity, log_audit_event
from src.infrastructure.auth.authentik_client import AuthentikClient
from src.infrastructure.auth.exceptions import (
    AuthentikAuthenticationError,
    AuthentikError,
)
from src.infrastructure.auth.token_validator import TokenValidator

logger = get_logger(__name__)


class TokenExchangeRequest(BaseModel):
    """Request model for token exchange."""

    authentik_token: str
    tenant_id: UUID


class TokenExchangeResponse(BaseModel):
    """Response model for token exchange."""

    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int = Field(description="Token expiration time in seconds")


class UserInfo(BaseModel):
    """User information from Authentik."""

    sub: str  # Subject (user ID in Authentik)
    email: str
    email_verified: bool = False
    name: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    preferred_username: str | None = None
    groups: list[str] = Field(default_factory=list)
    attributes: dict = Field(default_factory=dict)


class TokenExchangeService:
    """Handles token exchange between Authentik and internal JWT tokens."""

    def __init__(
        self,
        authentik_client: AuthentikClient,
        token_validator: TokenValidator,
        jwt_manager: JWTManager,
        user_service=None,  # User service will be injected when available
        session_service=None,  # Session service will be injected when available
    ):
        self.authentik_client = authentik_client
        self.token_validator = token_validator
        self.jwt_manager = jwt_manager
        self.user_service = user_service
        self.session_service = session_service

    async def exchange_token(
        self, request: TokenExchangeRequest
    ) -> TokenExchangeResponse:
        """Exchange an Authentik token for internal API tokens."""
        try:
            # Validate the Authentik token
            token_data = await self.token_validator.validate_token(
                request.authentik_token
            )

            # Extract user information from token
            user_info = UserInfo(
                sub=token_data.get("sub"),
                email=token_data.get("email", ""),
                email_verified=token_data.get("email_verified", False),
                name=token_data.get("name"),
                given_name=token_data.get("given_name"),
                family_name=token_data.get("family_name"),
                preferred_username=token_data.get("preferred_username"),
                groups=token_data.get("groups", []),
                attributes=token_data.get("attributes", {}),
            )

            # Verify user has access to the requested tenant
            if not await self._verify_tenant_access(user_info, request.tenant_id):
                logger.warning(
                    "User denied access to tenant",
                    user_id=user_info.sub,
                    tenant_id=str(request.tenant_id),
                    email=user_info.email,
                )
                raise AuthentikAuthenticationError("Access denied to requested tenant")

            # Get or create internal user
            internal_user_id = await self._get_or_create_user(
                user_info, request.tenant_id
            )

            # Create session
            session_id = await self._create_session(
                internal_user_id,
                request.tenant_id,
                authentik_session_id=token_data.get("sid"),
            )

            # Generate internal tokens
            access_token = self.jwt_manager.create_access_token(
                user_id=str(internal_user_id),
                tenant_id=str(request.tenant_id),
                session_id=str(session_id),
                scopes=self._extract_scopes(user_info),
                additional_claims={
                    "email": user_info.email,
                    "name": user_info.name,
                    "groups": user_info.groups,
                },
            )

            refresh_token = self.jwt_manager.create_refresh_token(
                user_id=str(internal_user_id),
                tenant_id=str(request.tenant_id),
                session_id=str(session_id),
            )

            # Log successful token exchange
            log_audit_event(
                event_type=AuditEventType.AUTH_TOKEN_EXCHANGED,
                user_id=str(internal_user_id),
                tenant_id=str(request.tenant_id),
                severity=AuditSeverity.LOW,
                details={
                    "authentik_user_id": user_info.sub,
                    "email": user_info.email,
                    "session_id": str(session_id),
                },
            )

            logger.info(
                "Token exchange successful",
                user_id=str(internal_user_id),
                tenant_id=str(request.tenant_id),
                session_id=str(session_id),
            )

            return TokenExchangeResponse(
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in=self.jwt_manager.access_token_expire_minutes * 60,
            )

        except AuthentikError as e:
            logger.error(
                "Authentik error during token exchange",
                error=str(e),
                tenant_id=str(request.tenant_id),
            )
            log_audit_event(
                event_type=AuditEventType.AUTH_TOKEN_EXCHANGE_FAILED,
                tenant_id=str(request.tenant_id),
                severity=AuditSeverity.MEDIUM,
                details={
                    "error": str(e),
                    "error_type": type(e).__name__,
                },
            )
            raise
        except Exception as e:
            logger.error(
                "Unexpected error during token exchange",
                error=str(e),
                tenant_id=str(request.tenant_id),
            )
            log_audit_event(
                event_type=AuditEventType.AUTH_TOKEN_EXCHANGE_FAILED,
                tenant_id=str(request.tenant_id),
                severity=AuditSeverity.HIGH,
                details={
                    "error": str(e),
                    "error_type": type(e).__name__,
                },
            )
            raise

    async def _verify_tenant_access(
        self, user_info: UserInfo, tenant_id: UUID
    ) -> bool:
        """Verify that the user has access to the requested tenant."""
        # Check if user has tenant-specific group
        tenant_group = f"tenant:{tenant_id}"
        if tenant_group in user_info.groups:
            return True

        # Check if user has admin group
        if "admins" in user_info.groups or "superusers" in user_info.groups:
            return True

        # Check tenant attributes
        allowed_tenants = user_info.attributes.get("allowed_tenants", [])
        if str(tenant_id) in allowed_tenants:
            return True

        # Additional tenant verification logic can be added here
        # For now, we'll be permissive if no specific restrictions exist
        return True

    async def _get_or_create_user(
        self, user_info: UserInfo, tenant_id: UUID
    ) -> UUID:
        """Get or create an internal user based on Authentik user info."""
        if not self.user_service:
            raise RuntimeError("User service is required for token exchange")

        # Use the user service to get or create user
        user = await self.user_service.get_or_create_by_external_id(
            external_id=user_info.sub,
            email=user_info.email,
            name=user_info.name,
            tenant_id=tenant_id,
            attributes=user_info.attributes,
        )
        return user.id

    async def _create_session(
        self,
        user_id: UUID,
        tenant_id: UUID,
        authentik_session_id: str | None = None,
    ) -> UUID:
        """Create a new session for the user."""
        if not self.session_service:
            raise RuntimeError("Session service is required for token exchange")

        # Use the session service to create session
        session_id = await self.session_service.create_session(
            user_id=user_id,
            tenant_id=tenant_id,
            external_session_id=authentik_session_id,
        )
        return session_id

    def _extract_scopes(self, user_info: UserInfo) -> list[str]:
        """Extract scopes/permissions from user info."""
        scopes = []

        # Map groups to scopes
        group_scope_mapping = {
            "admins": ["admin", "read", "write", "delete"],
            "users": ["read", "write"],
            "viewers": ["read"],
        }

        for group in user_info.groups:
            if group in group_scope_mapping:
                scopes.extend(group_scope_mapping[group])

        # Add custom scopes from attributes
        custom_scopes = user_info.attributes.get("scopes", [])
        if isinstance(custom_scopes, list):
            scopes.extend(custom_scopes)

        # Remove duplicates
        return list(set(scopes))

    async def refresh_token(self, refresh_token: str) -> TokenExchangeResponse:
        """Refresh access token using a refresh token."""
        try:
            # Decode and validate refresh token
            token_payload = self.jwt_manager.decode_refresh_token(refresh_token)

            # Verify session is still valid
            if self.session_service:
                session_valid = await self.session_service.validate_session(
                    UUID(token_payload.session_id)
                )
                if not session_valid:
                    raise AuthentikAuthenticationError("Session has been invalidated")

            # Generate new tokens
            new_access_token, new_refresh_token = self.jwt_manager.refresh_access_token(
                refresh_token
            )

            log_audit_event(
                event_type=AuditEventType.AUTH_TOKEN_REFRESHED,
                user_id=token_payload.sub,
                tenant_id=token_payload.tenant_id,
                severity=AuditSeverity.LOW,
                details={
                    "session_id": token_payload.session_id,
                },
            )

            return TokenExchangeResponse(
                access_token=new_access_token,
                refresh_token=new_refresh_token,
                expires_in=self.jwt_manager.access_token_expire_minutes * 60,
            )

        except Exception as e:
            logger.error(
                "Error refreshing token",
                error=str(e),
            )
            log_audit_event(
                event_type=AuditEventType.AUTH_TOKEN_REFRESH_FAILED,
                severity=AuditSeverity.MEDIUM,
                details={
                    "error": str(e),
                    "error_type": type(e).__name__,
                },
            )
            raise
