"""Tests for HTTP API client with retry logic."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from vaultsandbox.errors import ApiError, EmailNotFoundError, InboxNotFoundError, NetworkError
from vaultsandbox.http.api_client import ApiClient
from vaultsandbox.types import ClientConfig


@pytest.fixture
def config() -> ClientConfig:
    """Create a test client configuration."""
    return ClientConfig(
        api_key="test-api-key",
        base_url="https://test.example.com",
        timeout=5000,
        max_retries=2,
        retry_delay=100,  # Short delay for testing
        retry_on_status_codes=(429, 503),
        strategy=None,  # type: ignore
    )


@pytest.fixture
def api_client(config: ClientConfig) -> ApiClient:
    """Create an API client for testing."""
    return ApiClient(config)


class TestRetryOnStatusCode:
    """Tests for retry behavior on retryable status codes (lines 116-118)."""

    @pytest.mark.asyncio
    async def test_retry_on_429_status_code(self, api_client: ApiClient) -> None:
        """Test that 429 status code triggers retry with exponential backoff."""
        responses = [
            httpx.Response(429, text="Rate limited"),
            httpx.Response(429, text="Rate limited"),
            httpx.Response(200, json={"ok": True}),
        ]
        call_count = 0

        async def mock_request(*args, **kwargs):
            nonlocal call_count
            response = responses[call_count]
            call_count += 1
            return response

        mock_client = MagicMock()
        mock_client.is_closed = False
        mock_client.request = mock_request
        api_client._client = mock_client

        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            response = await api_client._request("GET", "/test")

        assert response.status_code == 200
        assert call_count == 3
        # Verify exponential backoff: delay * 2^attempt / 1000
        # First retry: 100 * 2^0 / 1000 = 0.1
        # Second retry: 100 * 2^1 / 1000 = 0.2
        assert mock_sleep.call_count == 2
        mock_sleep.assert_any_call(0.1)
        mock_sleep.assert_any_call(0.2)

    @pytest.mark.asyncio
    async def test_retry_on_503_status_code(self, api_client: ApiClient) -> None:
        """Test that 503 status code triggers retry."""
        responses = [
            httpx.Response(503, text="Service unavailable"),
            httpx.Response(200, json={"ok": True}),
        ]
        call_count = 0

        async def mock_request(*args, **kwargs):
            nonlocal call_count
            response = responses[call_count]
            call_count += 1
            return response

        mock_client = MagicMock()
        mock_client.is_closed = False
        mock_client.request = mock_request
        api_client._client = mock_client

        with patch("asyncio.sleep", new_callable=AsyncMock):
            response = await api_client._request("GET", "/test")

        assert response.status_code == 200
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_exhausted_retries_on_status_code_raises_error(
        self, api_client: ApiClient
    ) -> None:
        """Test that exhausting retries on retryable status raises ApiError."""

        # Always return 429 - will exhaust retries
        async def mock_request(*args, **kwargs):
            return httpx.Response(429, json={"message": "Too many requests"})

        mock_client = MagicMock()
        mock_client.is_closed = False
        mock_client.request = mock_request
        api_client._client = mock_client

        with patch("asyncio.sleep", new_callable=AsyncMock), pytest.raises(ApiError) as exc_info:
            await api_client._request("GET", "/test")

        assert exc_info.value.status_code == 429
        assert "Too many requests" in str(exc_info.value)


class TestErrorResponseHandling:
    """Tests for error response handling (lines 155-156, 164)."""

    @pytest.mark.asyncio
    async def test_non_json_error_response(self, api_client: ApiClient) -> None:
        """Test handling of non-JSON error response (lines 155-156)."""

        # Response with non-JSON body triggers ValueError/JSONDecodeError
        async def mock_request(*args, **kwargs):
            return httpx.Response(500, text="Internal Server Error - not JSON")

        mock_client = MagicMock()
        mock_client.is_closed = False
        mock_client.request = mock_request
        api_client._client = mock_client

        with pytest.raises(ApiError) as exc_info:
            await api_client._request("GET", "/test")

        assert exc_info.value.status_code == 500
        assert "Internal Server Error - not JSON" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_empty_error_response_body(self, api_client: ApiClient) -> None:
        """Test handling of empty error response body (line 156 fallback)."""

        async def mock_request(*args, **kwargs):
            return httpx.Response(500, text="")

        mock_client = MagicMock()
        mock_client.is_closed = False
        mock_client.request = mock_request
        api_client._client = mock_client

        with pytest.raises(ApiError) as exc_info:
            await api_client._request("GET", "/test")

        assert exc_info.value.status_code == 500
        assert "HTTP 500" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_404_default_inbox_not_found(self, api_client: ApiClient) -> None:
        """Test 404 defaults to InboxNotFoundError when no pattern matches (line 164)."""

        # Message doesn't match inbox or email patterns
        async def mock_request(*args, **kwargs):
            return httpx.Response(404, json={"message": "Resource not found"})

        mock_client = MagicMock()
        mock_client.is_closed = False
        mock_client.request = mock_request
        api_client._client = mock_client

        with pytest.raises(InboxNotFoundError) as exc_info:
            await api_client._request("GET", "/test")

        assert "Resource not found" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_404_inbox_pattern_match(self, api_client: ApiClient) -> None:
        """Test 404 with inbox pattern raises InboxNotFoundError."""

        async def mock_request(*args, **kwargs):
            return httpx.Response(404, json={"message": "Inbox not found"})

        mock_client = MagicMock()
        mock_client.is_closed = False
        mock_client.request = mock_request
        api_client._client = mock_client

        with pytest.raises(InboxNotFoundError):
            await api_client._request("GET", "/test")

    @pytest.mark.asyncio
    async def test_404_email_pattern_match(self, api_client: ApiClient) -> None:
        """Test 404 with email pattern raises EmailNotFoundError."""

        async def mock_request(*args, **kwargs):
            return httpx.Response(404, json={"message": "Email not found"})

        mock_client = MagicMock()
        mock_client.is_closed = False
        mock_client.request = mock_request
        api_client._client = mock_client

        with pytest.raises(EmailNotFoundError):
            await api_client._request("GET", "/test")


class TestNetworkErrorRetry:
    """Tests for network error retry behavior."""

    @pytest.mark.asyncio
    async def test_network_error_retries_and_succeeds(self, api_client: ApiClient) -> None:
        """Test network errors trigger retry and can succeed."""
        call_count = 0

        async def mock_request(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise httpx.ConnectError("Connection failed")
            return httpx.Response(200, json={"ok": True})

        mock_client = MagicMock()
        mock_client.is_closed = False
        mock_client.request = mock_request
        api_client._client = mock_client

        with patch("asyncio.sleep", new_callable=AsyncMock):
            response = await api_client._request("GET", "/test")

        assert response.status_code == 200
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_network_error_exhausts_retries(self, api_client: ApiClient) -> None:
        """Test network errors exhaust retries and raise NetworkError."""

        async def mock_request(*args, **kwargs):
            raise httpx.TimeoutException("Request timed out")

        mock_client = MagicMock()
        mock_client.is_closed = False
        mock_client.request = mock_request
        api_client._client = mock_client

        with (
            patch("asyncio.sleep", new_callable=AsyncMock),
            pytest.raises(NetworkError) as exc_info,
        ):
            await api_client._request("GET", "/test")

        assert "Network error" in str(exc_info.value)
        assert "Request timed out" in str(exc_info.value)


class TestCreateInbox:
    """Tests for create_inbox method."""

    @pytest.mark.asyncio
    async def test_create_inbox_with_encryption_parameter(self, api_client: ApiClient) -> None:
        """Test that encryption parameter is passed to API request body (line 239)."""
        captured_kwargs: dict = {}

        async def mock_request(*args, **kwargs):
            captured_kwargs.update(kwargs)
            return httpx.Response(
                200,
                json={
                    "emailAddress": "test@example.com",
                    "expiresAt": "2025-01-01T00:00:00Z",
                    "inboxHash": "test-hash",
                    "encrypted": False,
                },
            )

        mock_client = MagicMock()
        mock_client.is_closed = False
        mock_client.request = mock_request
        api_client._client = mock_client

        await api_client.create_inbox(encryption="plain")

        assert "json" in captured_kwargs
        assert captured_kwargs["json"]["encryption"] == "plain"
