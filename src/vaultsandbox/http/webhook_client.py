"""Webhook API client for VaultSandbox SDK."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from ..types import (
    CreateWebhookOptions,
    CustomTemplate,
    FilterConfig,
    FilterRule,
    RotateSecretResult,
    TestWebhookResult,
    UpdateWebhookOptions,
    WebhookData,
    WebhookListData,
    WebhookStats,
)
from .base_client import BaseApiClient, encode_path_segment


def validate_webhook_url(url: str, *, allow_http: bool = False) -> None:
    """Validate webhook URL format and protocol.

    Args:
        url: The webhook URL to validate.
        allow_http: If True, allow HTTP URLs. Default is False (HTTPS only).

    Raises:
        ValueError: If URL is invalid or uses HTTP without allow_http=True.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Webhook URL must use HTTP(S): {url}")

    if parsed.scheme == "http" and not allow_http:
        raise ValueError(f"Webhook URL must use HTTPS for security: {url}")

    if not parsed.netloc:
        raise ValueError(f"Webhook URL must have a host: {url}")


class WebhookApiClient(BaseApiClient):
    """API client for webhook operations.

    Provides methods for creating, updating, and managing webhooks.
    """

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
        *,
        allow_http: bool = False,
    ) -> WebhookData:
        """Create a webhook for an inbox.

        Args:
            email_address: The email address of the inbox.
            options: Webhook creation options.
            allow_http: If True, allow HTTP URLs. Default is False (HTTPS only).

        Returns:
            WebhookData with the created webhook information including secret.

        Raises:
            ValueError: If webhook URL is invalid or events list is empty.
        """
        validate_webhook_url(options.url, allow_http=allow_http)
        if not options.events:
            raise ValueError("At least one event type must be specified")

        encoded = encode_path_segment(email_address)
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
        encoded = encode_path_segment(email_address)
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
        encoded_addr = encode_path_segment(email_address)
        encoded_id = encode_path_segment(webhook_id)
        response = await self._request("GET", f"/api/inboxes/{encoded_addr}/webhooks/{encoded_id}")
        return self._parse_webhook_data(response.json())

    async def update_inbox_webhook(
        self,
        email_address: str,
        webhook_id: str,
        options: UpdateWebhookOptions,
        *,
        allow_http: bool = False,
    ) -> WebhookData:
        """Update a webhook for an inbox.

        Args:
            email_address: The email address of the inbox.
            webhook_id: The webhook ID.
            options: Update options.
            allow_http: If True, allow HTTP URLs. Default is False (HTTPS only).

        Returns:
            WebhookData with updated webhook information.

        Raises:
            ValueError: If webhook URL is invalid.
        """
        if options.url is not None:
            validate_webhook_url(options.url, allow_http=allow_http)

        encoded_addr = encode_path_segment(email_address)
        encoded_id = encode_path_segment(webhook_id)
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
        encoded_addr = encode_path_segment(email_address)
        encoded_id = encode_path_segment(webhook_id)
        await self._request("DELETE", f"/api/inboxes/{encoded_addr}/webhooks/{encoded_id}")

    async def test_inbox_webhook(self, email_address: str, webhook_id: str) -> TestWebhookResult:
        """Test a webhook for an inbox by sending a test event.

        Args:
            email_address: The email address of the inbox.
            webhook_id: The webhook ID.

        Returns:
            TestWebhookResult with test results.
        """
        encoded_addr = encode_path_segment(email_address)
        encoded_id = encode_path_segment(webhook_id)
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
        encoded_addr = encode_path_segment(email_address)
        encoded_id = encode_path_segment(webhook_id)
        response = await self._request(
            "POST", f"/api/inboxes/{encoded_addr}/webhooks/{encoded_id}/rotate-secret"
        )
        data = response.json()
        return RotateSecretResult(
            id=data["id"],
            secret=data["secret"],
            previous_secret_valid_until=data["previousSecretValidUntil"],
        )
