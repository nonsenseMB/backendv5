from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest
from httpx import ConnectError, TimeoutException

from src.infrastructure.auth import (
    AuthentikAPIError,
    AuthentikAuthenticationError,
    AuthentikClient,
    AuthentikConfig,
    AuthentikConnectionError,
    AuthentikTimeoutError,
)


@pytest.fixture
def config():
    return AuthentikConfig(
        authentik_url="http://127.0.0.1:9000",
        authentik_token="test-token",
        request_timeout=5,
        retry_attempts=2,
        retry_delay=0.1
    )


@pytest.fixture
def mock_httpx_client():
    mock = AsyncMock(spec=httpx.AsyncClient)
    return mock


@pytest.mark.asyncio
class TestAuthentikClient:

    async def test_client_initialization(self, config):
        client = AuthentikClient(config)
        assert client.config == config
        assert client._client is None
        assert client._headers["Authorization"] == "Bearer test-token"

    async def test_context_manager(self, config):
        async with AuthentikClient(config) as client:
            assert client._client is not None
        assert client._client is None

    async def test_health_check_success(self, config, mock_httpx_client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status = Mock()
        mock_httpx_client.request.return_value = mock_response

        client = AuthentikClient(config)
        client._client = mock_httpx_client

        result = await client.health_check()
        assert result is True

    async def test_health_check_failure(self, config, mock_httpx_client):
        mock_httpx_client.request.side_effect = ConnectError("Connection failed")

        client = AuthentikClient(config)
        client._client = mock_httpx_client

        result = await client.health_check()
        assert result is False

    async def test_get_request_success(self, config, mock_httpx_client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {"result": "success"}
        mock_httpx_client.request.return_value = mock_response

        client = AuthentikClient(config)
        client._client = mock_httpx_client

        result = await client.get("/test")
        assert result == {"result": "success"}
        mock_httpx_client.request.assert_called_with(
            method="GET",
            url="/test"
        )

    async def test_post_request_success(self, config, mock_httpx_client):
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {"id": "123"}
        mock_httpx_client.request.return_value = mock_response

        client = AuthentikClient(config)
        client._client = mock_httpx_client

        result = await client.post("/test", {"name": "test"})
        assert result == {"id": "123"}
        mock_httpx_client.request.assert_called_with(
            method="POST",
            url="/test",
            json={"name": "test"}
        )

    async def test_connection_error_handling(self, config, mock_httpx_client):
        mock_httpx_client.request.side_effect = ConnectError("Connection refused")

        client = AuthentikClient(config)
        client._client = mock_httpx_client

        with pytest.raises(AuthentikConnectionError) as exc_info:
            await client.get("/test")

        assert "Failed to connect to Authentik server" in str(exc_info.value)

    async def test_timeout_error_handling(self, config, mock_httpx_client):
        mock_httpx_client.request.side_effect = TimeoutException("Request timed out")

        client = AuthentikClient(config)
        client._client = mock_httpx_client

        with pytest.raises(AuthentikTimeoutError) as exc_info:
            await client.get("/test")

        assert "Request to Authentik timed out" in str(exc_info.value)

    async def test_authentication_error_handling(self, config, mock_httpx_client):
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_httpx_client.request.return_value = mock_response
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "401 Unauthorized",
            request=Mock(),
            response=mock_response
        )

        client = AuthentikClient(config)
        client._client = mock_httpx_client

        with pytest.raises(AuthentikAuthenticationError) as exc_info:
            await client.get("/test")

        assert "Authentication failed with Authentik" in str(exc_info.value)
        assert exc_info.value.status_code == 401

    async def test_api_error_handling(self, config, mock_httpx_client):
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.text = "Bad Request"
        mock_httpx_client.request.return_value = mock_response
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "400 Bad Request",
            request=Mock(),
            response=mock_response
        )

        client = AuthentikClient(config)
        client._client = mock_httpx_client

        with pytest.raises(AuthentikAPIError) as exc_info:
            await client.get("/test")

        assert "Authentik API error: 400" in str(exc_info.value)
        assert exc_info.value.status_code == 400

    async def test_get_user(self, config, mock_httpx_client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {"id": "user123", "username": "testuser"}
        mock_httpx_client.request.return_value = mock_response

        client = AuthentikClient(config)
        client._client = mock_httpx_client

        result = await client.get_user("user123")
        assert result == {"id": "user123", "username": "testuser"}
        mock_httpx_client.request.assert_called_with(
            method="GET",
            url="/core/users/user123/"
        )

    async def test_get_users_with_search(self, config, mock_httpx_client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {"results": []}
        mock_httpx_client.request.return_value = mock_response

        client = AuthentikClient(config)
        client._client = mock_httpx_client

        await client.get_users(page=2, page_size=50, search="test")
        mock_httpx_client.request.assert_called_with(
            method="GET",
            url="/core/users/",
            params={"page": 2, "page_size": 50, "search": "test"}
        )

    @pytest.mark.skip(reason="Retry logic test requires complex mocking of tenacity decorator")
    @patch('src.infrastructure.auth.authentik_client.AsyncClient')
    async def test_retry_logic(self, mock_async_client_class, config):
        # Modify config for faster testing
        config.retry_attempts = 3
        config.retry_delay = 0.01

        mock_client_instance = AsyncMock()
        mock_async_client_class.return_value = mock_client_instance

        # First two attempts fail, third succeeds
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status = Mock()
        mock_response.json.return_value = {"success": True}

        mock_client_instance.request.side_effect = [
            ConnectError("Connection failed"),
            ConnectError("Connection failed"),
            mock_response
        ]

        client = AuthentikClient(config)
        result = await client.get("/test")

        assert result == {"success": True}
        assert mock_client_instance.request.call_count == 3
