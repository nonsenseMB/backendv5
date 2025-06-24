"""Dependency injection for authentication services."""

from src.core.auth.jwt_manager import JWTManager
from src.domain.auth.user_service import UserService
from src.infrastructure.auth.authentik_client import AuthentikClient
from src.infrastructure.auth.redis_session_service import RedisSessionService
from src.infrastructure.auth.token_exchange import TokenExchangeService
from src.infrastructure.auth.token_validator import TokenValidator
from src.infrastructure.database.unit_of_work import UnitOfWork

# Singleton instances
_token_validator: TokenValidator | None = None
_jwt_manager: JWTManager | None = None
_authentik_client: AuthentikClient | None = None
_redis_session_service: RedisSessionService | None = None
_token_exchange_service: TokenExchangeService | None = None


def get_token_validator() -> TokenValidator:
    """Get singleton token validator instance."""
    global _token_validator
    if _token_validator is None:
        _token_validator = TokenValidator()
    return _token_validator


def get_jwt_manager() -> JWTManager:
    """Get singleton JWT manager instance."""
    global _jwt_manager
    if _jwt_manager is None:
        _jwt_manager = JWTManager()
    return _jwt_manager


def get_authentik_client() -> AuthentikClient:
    """Get singleton Authentik client instance."""
    global _authentik_client
    if _authentik_client is None:
        _authentik_client = AuthentikClient()
    return _authentik_client


async def get_redis_session_service() -> RedisSessionService:
    """Get singleton Redis session service instance."""
    global _redis_session_service
    if _redis_session_service is None:
        _redis_session_service = RedisSessionService()
    return _redis_session_service


async def get_token_exchange_service() -> TokenExchangeService:
    """Get singleton token exchange service instance."""
    global _token_exchange_service
    if _token_exchange_service is None:
        # Import here to avoid circular imports
        from src.infrastructure.database.session import AsyncSessionLocal

        # Create a session and UnitOfWork for UserService
        session = AsyncSessionLocal()
        uow = UnitOfWork(session)
        user_service = UserService(uow)

        # Get other dependencies
        authentik_client = get_authentik_client()
        token_validator = get_token_validator()
        jwt_manager = get_jwt_manager()
        session_service = await get_redis_session_service()

        # Create token exchange service with all dependencies
        _token_exchange_service = TokenExchangeService(
            authentik_client=authentik_client,
            token_validator=token_validator,
            jwt_manager=jwt_manager,
            user_service=user_service,
            session_service=session_service
        )
    return _token_exchange_service
