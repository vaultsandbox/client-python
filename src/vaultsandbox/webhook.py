"""Webhook class for VaultSandbox SDK."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

from .types import (
    CustomTemplate,
    FilterConfig,
    RotateSecretResult,
    TestWebhookResult,
    UpdateWebhookOptions,
    WebhookData,
    WebhookDeliveryStatus,
    WebhookScope,
    WebhookStats,
)
from .utils import parse_iso_timestamp, validate_webhook_id

if TYPE_CHECKING:
    from .http import ApiClient


@dataclass
class Webhook:
    """Represents a VaultSandbox webhook.

    Webhooks are scoped to individual inboxes. Each webhook only receives events
    for the specific inbox it was created on. The `inbox_email` property always
    contains the email address of the inbox this webhook belongs to.

    Webhooks allow you to receive real-time HTTP notifications when events occur
    in an inbox, such as new emails arriving.

    Attributes:
        id: Webhook ID (whk_ prefix).
        url: Target URL for webhook deliveries.
        events: Event types the webhook is subscribed to.
        scope: 'global' or 'inbox' (always 'inbox' for SDK-created webhooks).
        enabled: Whether the webhook is active.
        created_at: When the webhook was created.
        inbox_email: Email address of the inbox this webhook is scoped to.
        inbox_hash: Inbox hash (inbox webhooks only).
        secret: Signing secret for verifying payloads (whsec_ prefix).
        template: Payload template configuration.
        filter: Event filter configuration.
        description: Human-readable description.
        updated_at: When the webhook was last updated.
        last_delivery_at: When the last delivery attempt was made.
        last_delivery_status: Status of the last delivery.
        stats: Delivery statistics.
    """

    id: str
    url: str
    events: list[str]
    scope: WebhookScope
    enabled: bool
    created_at: datetime
    _api_client: ApiClient = field(repr=False)
    _inbox_email: str = field(repr=False)
    inbox_email: str | None = None
    inbox_hash: str | None = None
    secret: str | None = None
    template: str | CustomTemplate | None = None
    filter: FilterConfig | None = None
    description: str | None = None
    updated_at: datetime | None = None
    last_delivery_at: datetime | None = None
    last_delivery_status: WebhookDeliveryStatus | None = None
    stats: WebhookStats | None = None

    @classmethod
    def _from_data(
        cls,
        data: WebhookData,
        api_client: ApiClient,
        inbox_email: str,
    ) -> Webhook:
        """Create a Webhook from WebhookData.

        Args:
            data: The webhook data from the API.
            api_client: The API client instance.
            inbox_email: The parent inbox's email address.

        Returns:
            A Webhook instance.
        """
        return cls(
            id=data.id,
            url=data.url,
            events=data.events,
            scope=data.scope,
            enabled=data.enabled,
            created_at=parse_iso_timestamp(data.created_at),
            _api_client=api_client,
            _inbox_email=inbox_email,
            # Always expose the inbox email - use API response or fall back to parent
            inbox_email=data.inbox_email or inbox_email,
            inbox_hash=data.inbox_hash,
            secret=data.secret,
            template=data.template,
            filter=data.filter,
            description=data.description,
            updated_at=parse_iso_timestamp(data.updated_at) if data.updated_at else None,
            last_delivery_at=(
                parse_iso_timestamp(data.last_delivery_at) if data.last_delivery_at else None
            ),
            last_delivery_status=data.last_delivery_status,
            stats=data.stats,
        )

    def _update_from_data(self, data: WebhookData) -> None:
        """Update this webhook's fields from new data.

        Args:
            data: The updated webhook data from the API.
        """
        self.url = data.url
        self.events = data.events
        self.enabled = data.enabled
        self.template = data.template
        self.filter = data.filter
        self.description = data.description
        self.updated_at = parse_iso_timestamp(data.updated_at) if data.updated_at else None
        self.last_delivery_at = (
            parse_iso_timestamp(data.last_delivery_at) if data.last_delivery_at else None
        )
        self.last_delivery_status = data.last_delivery_status
        if data.stats:
            self.stats = data.stats
        if data.secret:
            self.secret = data.secret

    async def update(
        self,
        *,
        url: str | None = None,
        events: list[str] | None = None,
        template: str | CustomTemplate | None = None,
        remove_template: bool = False,
        filter: FilterConfig | None = None,
        remove_filter: bool = False,
        description: str | None = None,
        enabled: bool | None = None,
        allow_http: bool = False,
    ) -> None:
        """Update the webhook configuration.

        Args:
            url: New target URL.
            events: New event types to subscribe to.
            template: New template configuration.
            remove_template: Set True to remove the template.
            filter: New filter configuration.
            remove_filter: Set True to remove the filter.
            description: New description.
            enabled: Enable/disable the webhook.
            allow_http: If True, allow HTTP URLs (insecure). Default is False.

        Raises:
            ValueError: If the new URL is invalid.
        """
        options = UpdateWebhookOptions(
            url=url,
            events=events,
            template=template,
            filter=filter,
            description=description,
            enabled=enabled,
            _remove_template=remove_template,
            _remove_filter=remove_filter,
        )
        data = await self._api_client.update_inbox_webhook(
            self._inbox_email, self.id, options, allow_http=allow_http
        )
        self._update_from_data(data)

    async def delete(self) -> None:
        """Delete this webhook."""
        await self._api_client.delete_inbox_webhook(self._inbox_email, self.id)

    async def test(self) -> TestWebhookResult:
        """Send a test event to verify webhook connectivity.

        Returns:
            TestWebhookResult with the test results.
        """
        return await self._api_client.test_inbox_webhook(self._inbox_email, self.id)

    async def rotate_secret(self) -> RotateSecretResult:
        """Rotate the webhook signing secret.

        Generates a new signing secret. The old secret remains valid for 1 hour
        to allow time to update your webhook handler.

        Returns:
            RotateSecretResult with the new secret and grace period info.

        Raises:
            ValueError: If the webhook ID format is invalid.
        """
        validate_webhook_id(self.id)
        result = await self._api_client.rotate_inbox_webhook_secret(self._inbox_email, self.id)
        self.secret = result.secret
        return result

    async def enable(self) -> None:
        """Enable the webhook."""
        await self.update(enabled=True)

    async def disable(self) -> None:
        """Disable the webhook."""
        await self.update(enabled=False)

    async def refresh(self) -> None:
        """Refresh the webhook data from the server."""
        data = await self._api_client.get_inbox_webhook(self._inbox_email, self.id)
        self._update_from_data(data)
