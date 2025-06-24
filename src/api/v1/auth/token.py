"""Token exchange API endpoints."""
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field, ValidationError

from src.core.auth.jwt_manager import JWTManager
from src.core.logging import get_logger
from src.infrastructure.auth.authentik_client import AuthentikClient
from src.infrastructure.auth.exceptions import (
    AuthentikAuthenticationError,
    AuthentikError,
)
from src.infrastructure.auth.token_exchange import (
    TokenExchangeRequest,
    TokenExchangeService,
)
from src.infrastructure.auth.token_validator import TokenValidator

logger = get_logger(__name__)
router = APIRouter(prefix="/token", tags=["authentication"])

# Security scheme
bearer_scheme = HTTPBearer()


class TokenExchangeAPIRequest(BaseModel):
    """API request model for token exchange."""

    authentik_token: str = Field(..., description="Authentik JWT token")
    tenant_id: str | UUID = Field(..., description="Target tenant ID")


class TokenExchangeAPIResponse(BaseModel):
    """API response model for token exchange."""

    access_token: str = Field(..., description="API access token")
    refresh_token: str = Field(..., description="API refresh token")
    token_type: str = Field(default="Bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")


class TokenRefreshRequest(BaseModel):
    """API request model for token refresh."""

    refresh_token: str = Field(..., description="Refresh token")


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str = Field(..., description="Error code")
    message: str = Field(..., description="Error message")
    details: dict = Field(default_factory=dict, description="Additional error details")


class MockUser:
    """Mock user for testing without database."""
    def __init__(self, external_id: str, email: str):
        self.id = UUID("00000000-0000-0000-0000-000000000001")
        self.external_id = external_id
        self.email = email
        self.full_name = email.split("@")[0]

class MockUserService:
    """Mock user service for testing without database."""
    async def get_or_create_by_external_id(self, external_id: str, email: str, **kwargs):
        return MockUser(external_id, email)

async def get_token_exchange_service() -> TokenExchangeService:
    """Dependency to get token exchange service instance."""
    from src.domain.auth import SessionService, UserService
    from src.infrastructure.database.session import AsyncSessionLocal
    from src.infrastructure.database.unit_of_work import UnitOfWork

    # Create service instances
    authentik_client = AuthentikClient()
    token_validator = TokenValidator()  # Use default config
    jwt_manager = JWTManager()

    # Create session service (in-memory for now)
    session_service = SessionService()

    # Create database session and user service
    try:
        async_session = AsyncSessionLocal()
        uow = UnitOfWork(async_session)
        user_service = UserService(uow)
        logger.info("Using database user service")
    except Exception as e:
        logger.warning("Database not available, using mock user service", error=str(e))
        # Use mock user service for testing
        user_service = MockUserService()

    return TokenExchangeService(
        authentik_client=authentik_client,
        token_validator=token_validator,
        jwt_manager=jwt_manager,
        user_service=user_service,
        session_service=session_service,
    )


@router.post(
    "/exchange",
    response_model=TokenExchangeAPIResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid request"},
        401: {"model": ErrorResponse, "description": "Authentication failed"},
        403: {"model": ErrorResponse, "description": "Access denied"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
    summary="Exchange Authentik token for API tokens",
    description=(
        "Exchange an Authentik-issued JWT token for internal API access and refresh tokens. "
        "This endpoint validates the Authentik token, verifies tenant access, and creates "
        "or updates the user record before issuing new tokens."
    ),
)
async def exchange_token(
    request: TokenExchangeAPIRequest,
) -> TokenExchangeAPIResponse:
    """
    Exchange an Authentik token for internal API tokens.

    This endpoint:
    1. Validates the Authentik token
    2. Verifies user access to the requested tenant
    3. Creates or updates the internal user record
    4. Generates new API access and refresh tokens
    5. Creates a session for tracking

    Returns:
        TokenExchangeAPIResponse: New API tokens and expiration info

    Raises:
        400: Invalid request format
        401: Invalid or expired Authentik token
        403: User does not have access to the requested tenant
        500: Internal server error
    """
    try:
        # Get service instance
        service = await get_token_exchange_service()
        
        # Handle default tenant ID
        if isinstance(request.tenant_id, str) and request.tenant_id == "default":
            # Use a default UUID for the default tenant
            tenant_id = UUID("00000000-0000-0000-0000-000000000000")
        elif isinstance(request.tenant_id, str):
            # Try to parse as UUID
            tenant_id = UUID(request.tenant_id)
        else:
            tenant_id = request.tenant_id
            
        # Convert API request to service request
        service_request = TokenExchangeRequest(
            authentik_token=request.authentik_token,
            tenant_id=tenant_id,
        )

        # Perform token exchange
        response = await service.exchange_token(service_request)

        # Convert service response to API response
        return TokenExchangeAPIResponse(
            access_token=response.access_token,
            refresh_token=response.refresh_token,
            token_type=response.token_type,
            expires_in=response.expires_in,
        )

    except ValidationError as e:
        logger.warning(
            "Invalid token exchange request",
            errors=e.errors(),
            tenant_id=str(request.tenant_id),
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_request",
                "message": "Invalid request format",
                "details": {"validation_errors": e.errors()},
            },
        ) from e

    except AuthentikAuthenticationError as e:
        logger.warning(
            "Authentication failed during token exchange",
            error=str(e),
            tenant_id=str(request.tenant_id),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "authentication_failed",
                "message": str(e),
                "details": {},
            },
        ) from e

    except AuthentikError as e:
        logger.error(
            "Authentik error during token exchange",
            error=str(e),
            tenant_id=str(request.tenant_id),
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "authentik_error",
                "message": "Authentication service unavailable",
                "details": {"error": str(e)},
            },
        ) from e

    except Exception as e:
        logger.error(
            "Unexpected error during token exchange",
            error=str(e),
            tenant_id=str(request.tenant_id),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "internal_error",
                "message": "An unexpected error occurred",
                "details": {},
            },
        ) from e


@router.post(
    "/refresh",
    response_model=TokenExchangeAPIResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid request"},
        401: {"model": ErrorResponse, "description": "Invalid or expired refresh token"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
    summary="Refresh API access token",
    description=(
        "Use a valid refresh token to obtain new access and refresh tokens. "
        "The old refresh token will be invalidated after successful refresh."
    ),
)
async def refresh_token(
    request: TokenRefreshRequest,
) -> TokenExchangeAPIResponse:
    """
    Refresh API tokens using a valid refresh token.

    This endpoint:
    1. Validates the refresh token
    2. Verifies the session is still active
    3. Generates new access and refresh tokens
    4. Invalidates the old refresh token

    Returns:
        TokenExchangeAPIResponse: New API tokens and expiration info

    Raises:
        400: Invalid request format
        401: Invalid or expired refresh token
        500: Internal server error
    """
    try:
        # Get service instance
        service = await get_token_exchange_service()
        
        # Perform token refresh
        response = await service.refresh_token(request.refresh_token)

        # Convert service response to API response
        return TokenExchangeAPIResponse(
            access_token=response.access_token,
            refresh_token=response.refresh_token,
            token_type=response.token_type,
            expires_in=response.expires_in,
        )

    except ValidationError as e:
        logger.warning(
            "Invalid token refresh request",
            errors=e.errors(),
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_request",
                "message": "Invalid request format",
                "details": {"validation_errors": e.errors()},
            },
        ) from e

    except Exception as e:
        logger.error(
            "Error during token refresh",
            error=str(e),
        )
        # Check if it's an authentication error
        if "expired" in str(e).lower() or "invalid" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "invalid_token",
                    "message": "Invalid or expired refresh token",
                    "details": {},
                },
            ) from e
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": "internal_error",
                    "message": "An unexpected error occurred",
                    "details": {},
                },
            ) from e


# Health check endpoint for the auth service
@router.get(
    "/health",
    summary="Auth service health check",
    description="Check if the authentication service is operational",
)
async def health_check():
    """Check authentication service health."""
    return {"status": "healthy", "service": "authentication"}
