from typing import Any, TypeVar

import httpx
from httpx import AsyncClient, ConnectError, Response, TimeoutException
from tenacity import before_sleep_log, retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from src.core.logging import get_logger

from .config import AuthentikConfig
from .exceptions import (
    AuthentikAPIError,
    AuthentikAuthenticationError,
    AuthentikConnectionError,
    AuthentikError,
    AuthentikTimeoutError,
)

logger = get_logger(__name__)

T = TypeVar("T")


class AuthentikClient:
    """HTTP client for communicating with Authentik API"""

    def __init__(self, config: AuthentikConfig | None = None):
        self.config = config or AuthentikConfig()
        self._client: AsyncClient | None = None
        self._headers = {
            "Authorization": f"Bearer {self.config.authentik_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()

    async def connect(self):
        """Initialize the HTTP client"""
        if self._client is None:
            self._client = AsyncClient(
                base_url=self.config.api_base_url,
                headers=self._headers,
                timeout=httpx.Timeout(self.config.request_timeout),
                verify=self.config.verify_ssl
            )
            logger.info("Authentik client connected", base_url=self.config.api_base_url)

    async def disconnect(self):
        """Close the HTTP client"""
        if self._client:
            await self._client.aclose()
            self._client = None
            logger.info("Authentik client disconnected")

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type((ConnectError, TimeoutException)),
        before_sleep=before_sleep_log(logger, "WARNING")
    )
    async def _make_request(
        self,
        method: str,
        endpoint: str,
        **kwargs
    ) -> Response:
        """Make HTTP request with retry logic"""
        if not self._client:
            await self.connect()

        try:
            response = await self._client.request(
                method=method,
                url=endpoint,
                **kwargs
            )
            response.raise_for_status()
            return response

        except ConnectError as e:
            logger.error("Connection error to Authentik", error=str(e))
            raise AuthentikConnectionError(
                "Failed to connect to Authentik server",
                details={"error": str(e)}
            ) from e

        except TimeoutException as e:
            logger.error("Timeout connecting to Authentik", error=str(e))
            raise AuthentikTimeoutError(
                "Request to Authentik timed out",
                details={"timeout": self.config.request_timeout}
            ) from e

        except httpx.HTTPStatusError as e:
            logger.error(
                "HTTP error from Authentik",
                status_code=e.response.status_code,
                detail=e.response.text
            )

            if e.response.status_code == 401:
                raise AuthentikAuthenticationError(
                    "Authentication failed with Authentik",
                    status_code=401,
                    details={"response": e.response.text}
                ) from e

            raise AuthentikAPIError(
                f"Authentik API error: {e.response.status_code}",
                status_code=e.response.status_code,
                details={"response": e.response.text}
            ) from e

        except Exception as e:
            logger.error("Unexpected error calling Authentik", error=str(e))
            raise AuthentikError(
                "Unexpected error communicating with Authentik",
                details={"error": str(e)}
            ) from e

    async def get(self, endpoint: str, **kwargs) -> dict[str, Any]:
        """Make GET request to Authentik API"""
        response = await self._make_request("GET", endpoint, **kwargs)
        return response.json()

    async def post(self, endpoint: str, data: dict[str, Any], **kwargs) -> dict[str, Any]:
        """Make POST request to Authentik API"""
        response = await self._make_request("POST", endpoint, json=data, **kwargs)
        return response.json()

    async def put(self, endpoint: str, data: dict[str, Any], **kwargs) -> dict[str, Any]:
        """Make PUT request to Authentik API"""
        response = await self._make_request("PUT", endpoint, json=data, **kwargs)
        return response.json()

    async def patch(self, endpoint: str, data: dict[str, Any], **kwargs) -> dict[str, Any]:
        """Make PATCH request to Authentik API"""
        response = await self._make_request("PATCH", endpoint, json=data, **kwargs)
        return response.json()

    async def delete(self, endpoint: str, **kwargs) -> None:
        """Make DELETE request to Authentik API"""
        await self._make_request("DELETE", endpoint, **kwargs)

    async def health_check(self) -> bool:
        """Check if Authentik is accessible and responding"""
        try:
            # Use the admin API endpoint for health check
            response = await self._make_request("GET", "/admin/version/")
            return response.status_code == 200
        except AuthentikError:
            return False

    async def get_user(self, user_id: str) -> dict[str, Any]:
        """Get user details from Authentik"""
        return await self.get(f"/core/users/{user_id}/")

    async def get_users(
        self,
        page: int = 1,
        page_size: int = 100,
        search: str | None = None
    ) -> dict[str, Any]:
        """Get paginated list of users"""
        params = {
            "page": page,
            "page_size": page_size
        }
        if search:
            params["search"] = search

        return await self.get("/core/users/", params=params)

    async def get_groups(self, page: int = 1, page_size: int = 100) -> dict[str, Any]:
        """Get paginated list of groups"""
        return await self.get(
            "/core/groups/",
            params={"page": page, "page_size": page_size}
        )

    async def get_applications(self) -> dict[str, Any]:
        """Get list of applications"""
        return await self.get("/core/applications/")

    async def validate_token(self, token: str) -> dict[str, Any]:
        """Validate a token with Authentik"""
        # This would typically use a specific endpoint for token introspection
        # For now, this is a placeholder - actual implementation depends on
        # Authentik's token validation endpoint
        return await self.post(
            "/oauth2/introspect/",
            data={"token": token}
        )
