"""Tests for HTTP API client with retry logic."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from vaultsandbox.errors import (
    ApiError,
    EmailNotFoundError,
    InboxNotFoundError,
    NetworkError,
    WebhookLimitReachedError,
)
from vaultsandbox.http.api_client import ApiClient
from vaultsandbox.types import ClientConfig, FilterConfig, FilterRule


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

    @pytest.mark.asyncio
    async def test_create_inbox_with_spam_analysis_parameter(self, api_client: ApiClient) -> None:
        """Test that spam_analysis parameter is passed to API request body."""
        captured_kwargs: dict = {}

        async def mock_request(*args, **kwargs):
            captured_kwargs.update(kwargs)
            return httpx.Response(
                200,
                json={
                    "emailAddress": "test@example.com",
                    "expiresAt": "2025-01-01T00:00:00Z",
                    "inboxHash": "test-hash",
                    "encrypted": True,
                },
            )

        mock_client = MagicMock()
        mock_client.is_closed = False
        mock_client.request = mock_request
        api_client._client = mock_client

        await api_client.create_inbox(spam_analysis=True)

        assert "json" in captured_kwargs
        assert captured_kwargs["json"]["spamAnalysis"] is True


class TestWebhookLimitError:
    """Tests for webhook limit reached error handling (lines 194-195)."""

    @pytest.mark.asyncio
    async def test_409_webhook_limit_raises_error(self, api_client: ApiClient) -> None:
        """Test 409 with webhook limit pattern raises WebhookLimitReachedError."""

        async def mock_request(*args, **kwargs):
            return httpx.Response(409, json={"message": "Webhook limit reached"})

        mock_client = MagicMock()
        mock_client.is_closed = False
        mock_client.request = mock_request
        api_client._client = mock_client

        with pytest.raises(WebhookLimitReachedError) as exc_info:
            await api_client._request("GET", "/test")

        assert "Webhook limit" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_409_without_webhook_limit_raises_api_error(self, api_client: ApiClient) -> None:
        """Test 409 without webhook limit pattern raises generic ApiError."""

        async def mock_request(*args, **kwargs):
            return httpx.Response(409, json={"message": "Conflict error"})

        mock_client = MagicMock()
        mock_client.is_closed = False
        mock_client.request = mock_request
        api_client._client = mock_client

        with pytest.raises(ApiError) as exc_info:
            await api_client._request("GET", "/test")

        assert exc_info.value.status_code == 409
        assert "Conflict error" in str(exc_info.value)


class TestFilterSerialization:
    """Tests for filter rule/config serialization (lines 401, 411)."""

    def test_serialize_filter_rule_with_case_sensitive(self, api_client: ApiClient) -> None:
        """Test that case_sensitive=True is included in serialized output (line 401)."""
        rule = FilterRule(
            field="subject",
            operator="contains",
            value="test",
            case_sensitive=True,
        )

        result = api_client._serialize_filter_rule(rule)

        assert result["field"] == "subject"
        assert result["operator"] == "contains"
        assert result["value"] == "test"
        assert result["caseSensitive"] is True

    def test_serialize_filter_rule_without_case_sensitive(self, api_client: ApiClient) -> None:
        """Test that case_sensitive=False omits caseSensitive from output."""
        rule = FilterRule(
            field="subject",
            operator="contains",
            value="test",
            case_sensitive=False,
        )

        result = api_client._serialize_filter_rule(rule)

        assert "caseSensitive" not in result

    def test_serialize_filter_config_with_require_auth(self, api_client: ApiClient) -> None:
        """Test that require_auth=True is included in serialized output (line 411)."""
        rule = FilterRule(field="from", operator="equals", value="test@example.com")
        config = FilterConfig(
            rules=[rule],
            mode="all",
            require_auth=True,
        )

        result = api_client._serialize_filter_config(config)

        assert result["mode"] == "all"
        assert len(result["rules"]) == 1
        assert result["requireAuth"] is True

    def test_serialize_filter_config_without_require_auth(self, api_client: ApiClient) -> None:
        """Test that require_auth=False omits requireAuth from output."""
        rule = FilterRule(field="from", operator="equals", value="test@example.com")
        config = FilterConfig(
            rules=[rule],
            mode="all",
            require_auth=False,
        )

        result = api_client._serialize_filter_config(config)

        assert "requireAuth" not in result


class TestParseTemplate:
    """Tests for template parsing (line 455)."""

    def test_parse_template_unknown_dict_returns_none(self, api_client: ApiClient) -> None:
        """Test that unknown dict format returns None (line 455)."""
        # Dict without type="custom" should return None
        result = api_client._parse_template({"type": "unknown", "body": "test"})

        assert result is None


class TestWebhookUrlValidation:
    """Tests for webhook URL validation."""

    def test_invalid_url_scheme_raises_error(self) -> None:
        """Test that non-HTTP(S) URL scheme raises ValueError."""
        from vaultsandbox.http.webhook_client import validate_webhook_url

        with pytest.raises(ValueError, match="must use HTTP"):
            validate_webhook_url("ftp://example.com/webhook")

        with pytest.raises(ValueError, match="must use HTTP"):
            validate_webhook_url("file:///path/to/file")

    def test_http_url_without_allow_http_raises_error(self) -> None:
        """Test that HTTP URL without allow_http=True raises ValueError."""
        from vaultsandbox.http.webhook_client import validate_webhook_url

        with pytest.raises(ValueError, match="must use HTTPS for security"):
            validate_webhook_url("http://example.com/webhook")

    def test_http_url_with_allow_http_passes(self) -> None:
        """Test that HTTP URL with allow_http=True passes validation."""
        from vaultsandbox.http.webhook_client import validate_webhook_url

        # Should not raise
        validate_webhook_url("http://example.com/webhook", allow_http=True)

    def test_url_without_host_raises_error(self) -> None:
        """Test that URL without host raises ValueError."""
        from vaultsandbox.http.webhook_client import validate_webhook_url

        with pytest.raises(ValueError, match="must have a host"):
            validate_webhook_url("https:///webhook")

    @pytest.mark.asyncio
    async def test_create_webhook_empty_events_raises_error(self, api_client: ApiClient) -> None:
        """Test that creating webhook with empty events raises ValueError."""
        from vaultsandbox.types import CreateWebhookOptions

        options = CreateWebhookOptions(url="https://example.com/webhook", events=[])

        with pytest.raises(ValueError, match="At least one event type"):
            await api_client.create_inbox_webhook("test@example.com", options)


class TestInboxClientChaosFallback:
    """Tests for InboxApiClient chaos config fallback serialization."""

    def test_chaos_serialization_fallback_without_chaos_client(self) -> None:
        """Test fallback chaos serialization when _chaos_client is None."""
        from vaultsandbox.http.inbox_client import InboxApiClient
        from vaultsandbox.types import ChaosConfig, ClientConfig

        config = ClientConfig(
            api_key="test-key",
            base_url="https://test.example.com",
            timeout=5000,
            max_retries=2,
            retry_delay=100,
            retry_on_status_codes=(429, 503),
            strategy=None,  # type: ignore
        )

        inbox_client = InboxApiClient(config)
        # Ensure _chaos_client is None (default)
        inbox_client._chaos_client = None

        chaos = ChaosConfig(enabled=True, expires_at="2025-12-31T23:59:59Z")
        result = inbox_client._serialize_chaos_config(chaos)

        assert result["enabled"] is True
        assert result["expiresAt"] == "2025-12-31T23:59:59Z"

    def test_chaos_serialization_fallback_without_expires_at(self) -> None:
        """Test fallback chaos serialization without expires_at."""
        from vaultsandbox.http.inbox_client import InboxApiClient
        from vaultsandbox.types import ChaosConfig, ClientConfig

        config = ClientConfig(
            api_key="test-key",
            base_url="https://test.example.com",
            timeout=5000,
            max_retries=2,
            retry_delay=100,
            retry_on_status_codes=(429, 503),
            strategy=None,  # type: ignore
        )

        inbox_client = InboxApiClient(config)
        inbox_client._chaos_client = None

        chaos = ChaosConfig(enabled=False)
        result = inbox_client._serialize_chaos_config(chaos)

        assert result["enabled"] is False
        assert "expiresAt" not in result


class TestClientProperty:
    """Tests for _client property getter/setter."""

    def test_client_property_getter(self, api_client: ApiClient) -> None:
        """Test _client property returns the underlying httpx client."""
        mock_client = MagicMock()
        api_client._base._client = mock_client

        result = api_client._client

        assert result is mock_client

    @pytest.mark.asyncio
    async def test_get_client_method(self, api_client: ApiClient) -> None:
        """Test _get_client() returns httpx client."""
        mock_client = MagicMock()
        mock_client.is_closed = False
        api_client._base._client = mock_client

        result = await api_client._get_client()

        assert result is mock_client


class TestBackwardCompatibilityMethods:
    """Tests for backward compatibility wrapper methods on ApiClient."""

    def test_serialize_template_string(self, api_client: ApiClient) -> None:
        """Test _serialize_template with string template."""
        result = api_client._serialize_template("summary")

        assert result == "summary"

    def test_serialize_template_custom(self, api_client: ApiClient) -> None:
        """Test _serialize_template with CustomTemplate."""
        from vaultsandbox.types import CustomTemplate

        template = CustomTemplate(body='{"email": "{{email}}"}', content_type="application/json")

        result = api_client._serialize_template(template)

        assert result == {
            "type": "custom",
            "body": '{"email": "{{email}}"}',
            "contentType": "application/json",
        }

    def test_parse_filter_config(self, api_client: ApiClient) -> None:
        """Test _parse_filter_config parses filter from API response."""
        data = {
            "rules": [
                {"field": "from", "operator": "contains", "value": "test", "caseSensitive": True}
            ],
            "mode": "all",
            "requireAuth": True,
        }

        result = api_client._parse_filter_config(data)

        assert result.mode == "all"
        assert result.require_auth is True
        assert len(result.rules) == 1
        assert result.rules[0].field == "from"
        assert result.rules[0].case_sensitive is True

    def test_parse_webhook_stats(self, api_client: ApiClient) -> None:
        """Test _parse_webhook_stats parses stats from API response."""
        data = {
            "totalDeliveries": 100,
            "successfulDeliveries": 95,
            "failedDeliveries": 5,
        }

        result = api_client._parse_webhook_stats(data)

        assert result is not None
        assert result.total_deliveries == 100
        assert result.successful_deliveries == 95
        assert result.failed_deliveries == 5

    def test_parse_webhook_stats_none(self, api_client: ApiClient) -> None:
        """Test _parse_webhook_stats returns None for None input."""
        result = api_client._parse_webhook_stats(None)

        assert result is None

    def test_parse_webhook_data(self, api_client: ApiClient) -> None:
        """Test _parse_webhook_data parses webhook from API response."""
        data = {
            "id": "whk_123",
            "url": "https://example.com/webhook",
            "events": ["email.received"],
            "scope": "inbox",
            "enabled": True,
            "createdAt": "2025-01-01T00:00:00Z",
            "inboxEmail": "test@example.com",
            "inboxHash": "abc123",
        }

        result = api_client._parse_webhook_data(data)

        assert result.id == "whk_123"
        assert result.url == "https://example.com/webhook"
        assert result.events == ["email.received"]
        assert result.enabled is True


class TestChaosBackwardCompatibilityMethods:
    """Tests for chaos-related backward compatibility wrapper methods on ApiClient."""

    def test_serialize_latency_config(self, api_client: ApiClient) -> None:
        """Test _serialize_latency_config delegates to chaos client."""
        from vaultsandbox.types import LatencyConfig

        config = LatencyConfig(enabled=True, min_delay_ms=100, max_delay_ms=500)

        result = api_client._serialize_latency_config(config)

        assert result["enabled"] is True
        assert result["minDelayMs"] == 100
        assert result["maxDelayMs"] == 500

    def test_serialize_connection_drop_config(self, api_client: ApiClient) -> None:
        """Test _serialize_connection_drop_config delegates to chaos client."""
        from vaultsandbox.types import ConnectionDropConfig

        config = ConnectionDropConfig(enabled=True, probability=0.5)

        result = api_client._serialize_connection_drop_config(config)

        assert result["enabled"] is True
        assert result["probability"] == 0.5

    def test_serialize_random_error_config(self, api_client: ApiClient) -> None:
        """Test _serialize_random_error_config delegates to chaos client."""
        from vaultsandbox.types import RandomErrorConfig

        config = RandomErrorConfig(enabled=True, error_rate=0.3, error_types=["temporary"])

        result = api_client._serialize_random_error_config(config)

        assert result["enabled"] is True
        assert result["errorRate"] == 0.3
        assert result["errorTypes"] == ["temporary"]

    def test_serialize_greylist_config(self, api_client: ApiClient) -> None:
        """Test _serialize_greylist_config delegates to chaos client."""
        from vaultsandbox.types import GreylistConfig

        config = GreylistConfig(enabled=True, retry_window_ms=300000, max_attempts=3)

        result = api_client._serialize_greylist_config(config)

        assert result["enabled"] is True
        assert result["retryWindowMs"] == 300000
        assert result["maxAttempts"] == 3

    def test_serialize_blackhole_config(self, api_client: ApiClient) -> None:
        """Test _serialize_blackhole_config delegates to chaos client."""
        from vaultsandbox.types import BlackholeConfig

        config = BlackholeConfig(enabled=True, trigger_webhooks=True)

        result = api_client._serialize_blackhole_config(config)

        assert result["enabled"] is True
        assert result["triggerWebhooks"] is True

    def test_serialize_chaos_config(self, api_client: ApiClient) -> None:
        """Test _serialize_chaos_config delegates to chaos client."""
        from vaultsandbox.types import ChaosConfig

        config = ChaosConfig(enabled=True)

        result = api_client._serialize_chaos_config(config)

        assert result["enabled"] is True

    def test_parse_latency_config(self, api_client: ApiClient) -> None:
        """Test _parse_latency_config delegates to chaos client."""
        data = {"enabled": True, "minDelayMs": 100, "maxDelayMs": 500}

        result = api_client._parse_latency_config(data)

        assert result.enabled is True
        assert result.min_delay_ms == 100
        assert result.max_delay_ms == 500

    def test_parse_connection_drop_config(self, api_client: ApiClient) -> None:
        """Test _parse_connection_drop_config delegates to chaos client."""
        data = {"enabled": True, "probability": 0.5}

        result = api_client._parse_connection_drop_config(data)

        assert result.enabled is True
        assert result.probability == 0.5

    def test_parse_random_error_config(self, api_client: ApiClient) -> None:
        """Test _parse_random_error_config delegates to chaos client."""
        data = {"enabled": True, "errorRate": 0.3, "errorTypes": ["temporary"]}

        result = api_client._parse_random_error_config(data)

        assert result.enabled is True
        assert result.error_rate == 0.3
        assert result.error_types == ["temporary"]

    def test_parse_greylist_config(self, api_client: ApiClient) -> None:
        """Test _parse_greylist_config delegates to chaos client."""
        data = {"enabled": True, "retryWindowMs": 300000, "maxAttempts": 3}

        result = api_client._parse_greylist_config(data)

        assert result.enabled is True
        assert result.retry_window_ms == 300000
        assert result.max_attempts == 3

    def test_parse_blackhole_config(self, api_client: ApiClient) -> None:
        """Test _parse_blackhole_config delegates to chaos client."""
        data = {"enabled": True, "triggerWebhooks": True}

        result = api_client._parse_blackhole_config(data)

        assert result.enabled is True
        assert result.trigger_webhooks is True

    def test_parse_chaos_config(self, api_client: ApiClient) -> None:
        """Test _parse_chaos_config delegates to chaos client."""
        data = {"enabled": True}

        result = api_client._parse_chaos_config(data)

        assert result.enabled is True
