"""HTTP API client with retry logic for VaultSandbox SDK."""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any, cast
from urllib.parse import quote

import httpx

from ..errors import (
    ApiError,
    EmailNotFoundError,
    InboxNotFoundError,
    NetworkError,
    WebhookLimitReachedError,
    WebhookNotFoundError,
)
from ..types import (
    ClientConfig,
    CreateWebhookOptions,
    CustomTemplate,
    EmailResponse,
    EncryptionPolicy,
    FilterConfig,
    FilterRule,
    InboxData,
    InboxEncryptionMode,
    RawEmailResponse,
    RotateSecretResult,
    ServerInfo,
    SyncStatus,
    TestWebhookResult,
    UpdateWebhookOptions,
    WebhookData,
    WebhookListData,
    WebhookStats,
)

# More robust patterns for error classification
_INBOX_NOT_FOUND_PATTERN = re.compile(r"\binbox\b.*\b(not found|does not exist)\b", re.IGNORECASE)
_EMAIL_NOT_FOUND_PATTERN = re.compile(r"\bemail\b.*\b(not found|does not exist)\b", re.IGNORECASE)
_WEBHOOK_NOT_FOUND_PATTERN = re.compile(
    r"\bwebhook\b.*\b(not found|does not exist)\b", re.IGNORECASE
)
_WEBHOOK_LIMIT_PATTERN = re.compile(r"\bwebhook\b.*\blimit\b", re.IGNORECASE)


def _encode_path_segment(value: str) -> str:
    """URL-encode a path segment for use in API URLs.

    Args:
        value: The value to encode.

    Returns:
        URL-encoded string safe for use in URL paths.
    """
    return quote(value, safe="")


class ApiClient:
    """HTTP client for VaultSandbox API with automatic retry logic.

    Attributes:
        config: Client configuration.
    """

    def __init__(self, config: ClientConfig) -> None:
        """Initialize the API client.

        Args:
            config: Client configuration with API key and settings.
        """
        self.config = config
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client.

        Returns:
            The HTTP client instance.
        """
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.config.base_url,
                headers={
                    "X-API-Key": self.config.api_key,
                    "Content-Type": "application/json",
                },
                timeout=httpx.Timeout(self.config.timeout / 1000),
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """Make an HTTP request with retry logic.

        Args:
            method: HTTP method (GET, POST, DELETE, PATCH).
            path: API path.
            json: JSON body for the request.
            params: Query parameters.

        Returns:
            The HTTP response.

        Raises:
            ApiError: If the request fails after all retries.
            NetworkError: If there's a network communication failure.
            InboxNotFoundError: If the inbox is not found.
            EmailNotFoundError: If the email is not found.
        """
        client = await self._get_client()
        last_error: Exception | None = None

        for attempt in range(self.config.max_retries + 1):
            try:
                response = await client.request(method, path, json=json, params=params)

                # Check if we should retry based on status code
                if (
                    response.status_code in self.config.retry_on_status_codes
                    and attempt < self.config.max_retries
                ):
                    delay = self.config.retry_delay * (2**attempt) / 1000
                    await asyncio.sleep(delay)
                    continue

                # Handle errors
                if response.status_code >= 400:
                    self._handle_error_response(response)

                return response

            except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as e:
                last_error = e
                if attempt < self.config.max_retries:
                    delay = self.config.retry_delay * (2**attempt) / 1000
                    await asyncio.sleep(delay)
                    continue
                raise NetworkError(f"Network error: {e}") from e

        # Should not reach here, but just in case
        if last_error:  # pragma: no cover
            raise NetworkError(
                f"Request failed after {self.config.max_retries} retries"
            ) from last_error
        raise NetworkError(
            f"Request failed after {self.config.max_retries} retries"
        )  # pragma: no cover

    def _handle_error_response(self, response: httpx.Response) -> None:
        """Handle HTTP error responses.

        Args:
            response: The HTTP response.

        Raises:
            InboxNotFoundError: If the inbox is not found.
            EmailNotFoundError: If the email is not found.
            WebhookNotFoundError: If the webhook is not found.
            WebhookLimitReachedError: If the webhook limit is reached.
            ApiError: For other API errors.
        """
        try:
            data = response.json()
            message = data.get("message", data.get("error", response.text))
        except (ValueError, json.JSONDecodeError):
            message = response.text or f"HTTP {response.status_code}"

        if response.status_code == 404:
            if _WEBHOOK_NOT_FOUND_PATTERN.search(message):
                raise WebhookNotFoundError(message)
            if _INBOX_NOT_FOUND_PATTERN.search(message):
                raise InboxNotFoundError(message)
            if _EMAIL_NOT_FOUND_PATTERN.search(message):
                raise EmailNotFoundError(message)
            # Default to inbox not found for 404
            raise InboxNotFoundError(message)

        if response.status_code == 409 and _WEBHOOK_LIMIT_PATTERN.search(message):
            raise WebhookLimitReachedError(message)

        raise ApiError(response.status_code, message)

    # Server endpoints

    async def check_key(self) -> bool:
        """Validate the API key.

        Returns:
            True if the API key is valid.
        """
        response = await self._request("GET", "/api/check-key")
        data = response.json()
        return cast(bool, data.get("ok", False))

    async def get_server_info(self) -> ServerInfo:
        """Get server information and capabilities.

        Returns:
            ServerInfo with cryptographic configuration.
        """
        response = await self._request("GET", "/api/server-info")
        data = response.json()
        # Default to 'always' if not specified (backwards compatibility)
        encryption_policy: EncryptionPolicy = data.get("encryptionPolicy", "always")
        return ServerInfo(
            server_sig_pk=data["serverSigPk"],
            algs=data["algs"],
            context=data["context"],
            max_ttl=data["maxTtl"],
            default_ttl=data["defaultTtl"],
            sse_console=data.get("sseConsole", False),
            allowed_domains=data.get("allowedDomains", []),
            encryption_policy=encryption_policy,
        )

    # Inbox endpoints

    async def create_inbox(
        self,
        client_kem_pk: str | None = None,
        *,
        ttl: int | None = None,
        email_address: str | None = None,
        email_auth: bool | None = None,
        encryption: InboxEncryptionMode | None = None,
    ) -> InboxData:
        """Create a new inbox.

        Args:
            client_kem_pk: Base64url-encoded ML-KEM-768 public key.
                Required for encrypted inboxes, omit for plain inboxes.
            ttl: Time-to-live in seconds.
            email_address: Desired email address or domain.
            email_auth: Enable/disable email authentication checks. None uses server default.
            encryption: Encryption mode ('encrypted' or 'plain'). None uses server default.

        Returns:
            InboxData with the created inbox information.
        """
        body: dict[str, Any] = {}
        if client_kem_pk is not None:
            body["clientKemPk"] = client_kem_pk
        if ttl is not None:
            body["ttl"] = ttl
        if email_address is not None:
            body["emailAddress"] = email_address
        if email_auth is not None:
            body["emailAuth"] = email_auth
        if encryption is not None:
            body["encryption"] = encryption

        response = await self._request("POST", "/api/inboxes", json=body)
        data = response.json()
        return InboxData(
            email_address=data["emailAddress"],
            expires_at=data["expiresAt"],
            inbox_hash=data["inboxHash"],
            encrypted=data.get("encrypted", True),  # Default to True for backwards compat
            email_auth=data.get("emailAuth", False),
            server_sig_pk=data.get("serverSigPk"),  # Optional, only present when encrypted
        )

    async def delete_inbox(self, email_address: str) -> None:
        """Delete a specific inbox.

        Args:
            email_address: The email address of the inbox to delete.
        """
        encoded = _encode_path_segment(email_address)
        await self._request("DELETE", f"/api/inboxes/{encoded}")

    async def delete_all_inboxes(self) -> int:  # pragma: no cover
        """Delete all inboxes for the API key.

        Note: Not tested in integration tests as it would interfere with
        concurrent test runs by deleting all inboxes for the API key.

        Returns:
            Number of inboxes deleted.
        """
        response = await self._request("DELETE", "/api/inboxes")
        data = response.json()
        return cast(int, data.get("deleted", 0))

    async def get_sync_status(self, email_address: str) -> SyncStatus:
        """Get inbox sync status.

        Args:
            email_address: The email address of the inbox.

        Returns:
            SyncStatus with email count and hash.
        """
        encoded = _encode_path_segment(email_address)
        response = await self._request("GET", f"/api/inboxes/{encoded}/sync")
        data = response.json()
        return SyncStatus(
            email_count=data["emailCount"],
            emails_hash=data["emailsHash"],
        )

    # Email endpoints

    async def list_emails(
        self, email_address: str, include_content: bool = False
    ) -> list[EmailResponse]:
        """List all emails in an inbox.

        Args:
            email_address: The email address of the inbox.
            include_content: If True, include full email content in response.

        Returns:
            List of encrypted email responses.
        """
        encoded = _encode_path_segment(email_address)
        params = {"includeContent": "true"} if include_content else None
        response = await self._request("GET", f"/api/inboxes/{encoded}/emails", params=params)
        return cast(list[EmailResponse], response.json())

    async def get_email(self, email_address: str, email_id: str) -> EmailResponse:
        """Get a specific email.

        Args:
            email_address: The email address of the inbox.
            email_id: The email ID.

        Returns:
            Encrypted email response.
        """
        encoded_addr = _encode_path_segment(email_address)
        encoded_id = _encode_path_segment(email_id)
        response = await self._request("GET", f"/api/inboxes/{encoded_addr}/emails/{encoded_id}")
        return cast(EmailResponse, response.json())

    async def get_raw_email(self, email_address: str, email_id: str) -> RawEmailResponse:
        """Get raw email source.

        Args:
            email_address: The email address of the inbox.
            email_id: The email ID.

        Returns:
            Raw email response with encrypted content.
        """
        encoded_addr = _encode_path_segment(email_address)
        encoded_id = _encode_path_segment(email_id)
        response = await self._request(
            "GET", f"/api/inboxes/{encoded_addr}/emails/{encoded_id}/raw"
        )
        return cast(RawEmailResponse, response.json())

    async def mark_email_as_read(self, email_address: str, email_id: str) -> None:
        """Mark an email as read.

        Args:
            email_address: The email address of the inbox.
            email_id: The email ID.
        """
        encoded_addr = _encode_path_segment(email_address)
        encoded_id = _encode_path_segment(email_id)
        await self._request("PATCH", f"/api/inboxes/{encoded_addr}/emails/{encoded_id}/read")

    async def delete_email(self, email_address: str, email_id: str) -> None:
        """Delete an email.

        Args:
            email_address: The email address of the inbox.
            email_id: The email ID.
        """
        encoded_addr = _encode_path_segment(email_address)
        encoded_id = _encode_path_segment(email_id)
        await self._request("DELETE", f"/api/inboxes/{encoded_addr}/emails/{encoded_id}")

    # Inbox webhook endpoints

    def _serialize_filter_rule(self, rule: FilterRule) -> dict[str, Any]:
        """Serialize a FilterRule to API format."""
        result: dict[str, Any] = {
            "field": rule.field,
            "operator": rule.operator,
            "value": rule.value,
        }
        if rule.case_sensitive:
            result["caseSensitive"] = True
        return result

    def _serialize_filter_config(self, filter_config: FilterConfig) -> dict[str, Any]:
        """Serialize a FilterConfig to API format."""
        result: dict[str, Any] = {
            "rules": [self._serialize_filter_rule(r) for r in filter_config.rules],
            "mode": filter_config.mode,
        }
        if filter_config.require_auth:
            result["requireAuth"] = True
        return result

    def _serialize_template(self, template: str | CustomTemplate) -> str | dict[str, Any]:
        """Serialize a template to API format."""
        if isinstance(template, str):
            return template
        # CustomTemplate
        result: dict[str, Any] = {
            "type": "custom",
            "body": template.body,
        }
        if template.content_type:
            result["contentType"] = template.content_type
        return result

    def _parse_filter_config(self, data: dict[str, Any]) -> FilterConfig:
        """Parse filter config from API response."""
        rules = [
            FilterRule(
                field=r["field"],
                operator=r["operator"],
                value=r["value"],
                case_sensitive=r.get("caseSensitive", False),
            )
            for r in data.get("rules", [])
        ]
        return FilterConfig(
            rules=rules,
            mode=data["mode"],
            require_auth=data.get("requireAuth", False),
        )

    def _parse_template(self, data: Any) -> str | CustomTemplate | None:
        """Parse template from API response."""
        if data is None:
            return None
        if isinstance(data, str):
            return data
        if isinstance(data, dict) and data.get("type") == "custom":
            return CustomTemplate(
                body=data["body"],
                content_type=data.get("contentType"),
            )
        return None

    def _parse_webhook_stats(self, data: dict[str, Any] | None) -> WebhookStats | None:
        """Parse webhook stats from API response."""
        if data is None:
            return None
        return WebhookStats(
            total_deliveries=data["totalDeliveries"],
            successful_deliveries=data["successfulDeliveries"],
            failed_deliveries=data["failedDeliveries"],
        )

    def _parse_webhook_data(self, data: dict[str, Any]) -> WebhookData:
        """Parse WebhookData from API response."""
        return WebhookData(
            id=data["id"],
            url=data["url"],
            events=data["events"],
            scope=data["scope"],
            enabled=data["enabled"],
            created_at=data["createdAt"],
            inbox_email=data.get("inboxEmail"),
            inbox_hash=data.get("inboxHash"),
            secret=data.get("secret"),
            template=self._parse_template(data.get("template")),
            filter=self._parse_filter_config(data["filter"]) if data.get("filter") else None,
            description=data.get("description"),
            updated_at=data.get("updatedAt"),
            last_delivery_at=data.get("lastDeliveryAt"),
            last_delivery_status=data.get("lastDeliveryStatus"),
            stats=self._parse_webhook_stats(data.get("stats")),
        )

    async def create_inbox_webhook(
        self,
        email_address: str,
        options: CreateWebhookOptions,
    ) -> WebhookData:
        """Create a webhook for an inbox.

        Args:
            email_address: The email address of the inbox.
            options: Webhook creation options.

        Returns:
            WebhookData with the created webhook information including secret.
        """
        encoded = _encode_path_segment(email_address)
        body: dict[str, Any] = {
            "url": options.url,
            "events": options.events,
        }
        if options.template is not None:
            body["template"] = self._serialize_template(options.template)
        if options.filter is not None:
            body["filter"] = self._serialize_filter_config(options.filter)
        if options.description is not None:
            body["description"] = options.description

        response = await self._request("POST", f"/api/inboxes/{encoded}/webhooks", json=body)
        return self._parse_webhook_data(response.json())

    async def list_inbox_webhooks(self, email_address: str) -> WebhookListData:
        """List all webhooks for an inbox.

        Args:
            email_address: The email address of the inbox.

        Returns:
            WebhookListData with list of webhooks and total count.
        """
        encoded = _encode_path_segment(email_address)
        response = await self._request("GET", f"/api/inboxes/{encoded}/webhooks")
        data = response.json()
        return WebhookListData(
            webhooks=[self._parse_webhook_data(w) for w in data["webhooks"]],
            total=data["total"],
        )

    async def get_inbox_webhook(self, email_address: str, webhook_id: str) -> WebhookData:
        """Get a specific webhook for an inbox.

        Args:
            email_address: The email address of the inbox.
            webhook_id: The webhook ID.

        Returns:
            WebhookData with webhook information including secret and stats.
        """
        encoded_addr = _encode_path_segment(email_address)
        encoded_id = _encode_path_segment(webhook_id)
        response = await self._request("GET", f"/api/inboxes/{encoded_addr}/webhooks/{encoded_id}")
        return self._parse_webhook_data(response.json())

    async def update_inbox_webhook(
        self,
        email_address: str,
        webhook_id: str,
        options: UpdateWebhookOptions,
    ) -> WebhookData:
        """Update a webhook for an inbox.

        Args:
            email_address: The email address of the inbox.
            webhook_id: The webhook ID.
            options: Update options.

        Returns:
            WebhookData with updated webhook information.
        """
        encoded_addr = _encode_path_segment(email_address)
        encoded_id = _encode_path_segment(webhook_id)
        body: dict[str, Any] = {}

        if options.url is not None:
            body["url"] = options.url
        if options.events is not None:
            body["events"] = options.events
        if options._remove_template:
            body["template"] = None
        elif options.template is not None:
            body["template"] = self._serialize_template(options.template)
        if options._remove_filter:
            body["filter"] = None
        elif options.filter is not None:
            body["filter"] = self._serialize_filter_config(options.filter)
        if options.description is not None:
            body["description"] = options.description
        if options.enabled is not None:
            body["enabled"] = options.enabled

        response = await self._request(
            "PATCH", f"/api/inboxes/{encoded_addr}/webhooks/{encoded_id}", json=body
        )
        return self._parse_webhook_data(response.json())

    async def delete_inbox_webhook(self, email_address: str, webhook_id: str) -> None:
        """Delete a webhook for an inbox.

        Args:
            email_address: The email address of the inbox.
            webhook_id: The webhook ID.
        """
        encoded_addr = _encode_path_segment(email_address)
        encoded_id = _encode_path_segment(webhook_id)
        await self._request("DELETE", f"/api/inboxes/{encoded_addr}/webhooks/{encoded_id}")

    async def test_inbox_webhook(self, email_address: str, webhook_id: str) -> TestWebhookResult:
        """Test a webhook for an inbox by sending a test event.

        Args:
            email_address: The email address of the inbox.
            webhook_id: The webhook ID.

        Returns:
            TestWebhookResult with test results.
        """
        encoded_addr = _encode_path_segment(email_address)
        encoded_id = _encode_path_segment(webhook_id)
        response = await self._request(
            "POST", f"/api/inboxes/{encoded_addr}/webhooks/{encoded_id}/test"
        )
        data = response.json()
        return TestWebhookResult(
            success=data["success"],
            status_code=data.get("statusCode"),
            response_time=data.get("responseTime"),
            response_body=data.get("responseBody"),
            error=data.get("error"),
            payload_sent=data.get("payloadSent"),
        )

    async def rotate_inbox_webhook_secret(
        self, email_address: str, webhook_id: str
    ) -> RotateSecretResult:
        """Rotate the signing secret for an inbox webhook.

        Args:
            email_address: The email address of the inbox.
            webhook_id: The webhook ID.

        Returns:
            RotateSecretResult with new secret and grace period info.
        """
        encoded_addr = _encode_path_segment(email_address)
        encoded_id = _encode_path_segment(webhook_id)
        response = await self._request(
            "POST", f"/api/inboxes/{encoded_addr}/webhooks/{encoded_id}/rotate-secret"
        )
        data = response.json()
        return RotateSecretResult(
            id=data["id"],
            secret=data["secret"],
            previous_secret_valid_until=data["previousSecretValidUntil"],
        )
