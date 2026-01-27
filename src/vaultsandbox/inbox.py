"""Inbox class for VaultSandbox SDK."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from .crypto import Keypair, decrypt_metadata, to_base64url
from .crypto.constants import EXPORT_VERSION
from .email import Email
from .errors import InvalidPayloadError, TimeoutError
from .strategies import Subscription
from .types import (
    BlackholeConfig,
    ChaosConfig,
    ConnectionDropConfig,
    CreateWebhookOptions,
    CustomTemplate,
    EmailMetadata,
    ExportedInbox,
    FilterConfig,
    GreylistConfig,
    LatencyConfig,
    RandomErrorConfig,
    SyncStatus,
    WaitForCountOptions,
    WaitForEmailOptions,
)
from .utils import parse_iso_timestamp, validate_email_id
from .utils.email_utils import matches_filter
from .webhook import Webhook

if TYPE_CHECKING:
    from .http import ApiClient
    from .strategies import DeliveryStrategy
    from .types import RawEmail


@dataclass
class Inbox:
    """Represents a VaultSandbox email inbox.

    Attributes:
        email_address: The email address assigned to the inbox.
        expires_at: Timestamp when the inbox will expire.
        inbox_hash: SHA-256 hash of the client KEM public key (or email for plain inboxes).
        encrypted: Whether the inbox uses encryption.
        server_sig_pk: Server signing public key for verification (only for encrypted inboxes).
        email_auth: Whether email authentication checks are enabled.
    """

    email_address: str
    expires_at: datetime
    inbox_hash: str
    _api_client: ApiClient = field(repr=False)
    _strategy: DeliveryStrategy = field(repr=False)
    encrypted: bool = True
    server_sig_pk: str | None = None
    email_auth: bool = True
    _keypair: Keypair | None = field(default=None, repr=False)
    _subscriptions: list[Subscription] = field(default_factory=list, repr=False)

    async def list_emails(self) -> list[Email]:
        """List all emails in the inbox with full content.

        Returns:
            List of Email objects with full content.
        """
        list_responses = await self._api_client.list_emails(
            self.email_address, include_content=True
        )
        return [Email._from_response(email_data, self) for email_data in list_responses]

    async def list_emails_metadata_only(self) -> list[EmailMetadata]:
        """List all emails in the inbox with metadata only.

        This is more efficient than list_emails() when you only need
        basic information like subject and sender.

        Returns:
            List of EmailMetadata objects.

        Raises:
            InvalidPayloadError: If email metadata cannot be decoded.
        """
        import base64
        import binascii
        import json

        list_responses = await self._api_client.list_emails(
            self.email_address, include_content=False
        )
        emails = []
        for email_data in list_responses:
            # Check if this is an encrypted or plain email
            if "encryptedMetadata" in email_data:
                # Encrypted email - decrypt metadata
                if self._keypair is None:  # pragma: no cover
                    raise RuntimeError("Encrypted email received but inbox has no keypair")
                metadata = decrypt_metadata(
                    email_data["encryptedMetadata"],
                    self._keypair,
                    pinned_server_key=self.server_sig_pk,
                )
            else:
                # Plain email - decode base64 JSON
                metadata_b64 = email_data.get("metadata", "")
                try:
                    metadata = json.loads(base64.b64decode(metadata_b64).decode("utf-8"))
                except (binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as e:
                    raise InvalidPayloadError(f"Failed to decode email metadata: {e}") from e

            emails.append(
                EmailMetadata(
                    id=email_data["id"],
                    from_address=metadata.get("from", ""),
                    subject=metadata.get("subject", ""),
                    received_at=parse_iso_timestamp(metadata.get("receivedAt", "")),
                    is_read=email_data.get("isRead", False),
                )
            )
        return emails

    async def get_email(self, email_id: str) -> Email:
        """Get a specific email by ID.

        Args:
            email_id: The email ID.

        Returns:
            The Email object.
        """
        response = await self._api_client.get_email(self.email_address, email_id)
        return Email._from_response(response, self)

    async def get_raw_email(self, email_id: str) -> RawEmail:
        """Get the raw MIME source of an email.

        Args:
            email_id: The email ID.

        Returns:
            RawEmail object with id and raw MIME content.

        Raises:
            InvalidPayloadError: If raw email content cannot be decoded.
        """
        import base64
        import binascii

        from .crypto import decrypt_raw
        from .types import RawEmail

        raw_response = await self._api_client.get_raw_email(self.email_address, email_id)

        # Check if this is an encrypted or plain email
        if "encryptedRaw" in raw_response:
            # Encrypted email - decrypt
            if self._keypair is None:  # pragma: no cover
                raise RuntimeError("Encrypted email received but inbox has no keypair")
            # Pass pinned server key for validation per Section 8.1 step 5
            raw = decrypt_raw(
                raw_response["encryptedRaw"],
                self._keypair,
                pinned_server_key=self.server_sig_pk,
            )
        else:
            # Plain email - decode base64
            try:
                raw = base64.b64decode(raw_response.get("raw", "")).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError) as e:
                raise InvalidPayloadError(f"Failed to decode raw email: {e}") from e

        return RawEmail(id=raw_response["id"], raw=raw)

    async def mark_email_as_read(self, email_id: str) -> None:
        """Mark an email as read.

        Args:
            email_id: The email ID.
        """
        await self._api_client.mark_email_as_read(self.email_address, email_id)

    async def delete_email(self, email_id: str) -> None:
        """Delete an email.

        Args:
            email_id: The email ID.

        Raises:
            ValueError: If the email ID format is invalid.
        """
        validate_email_id(email_id)
        await self._api_client.delete_email(self.email_address, email_id)

    async def delete(self) -> None:
        """Delete this inbox."""
        # Unsubscribe from all subscriptions
        for subscription in self._subscriptions:
            await self._strategy.unsubscribe(subscription)
        self._subscriptions.clear()

        await self._api_client.delete_inbox(self.email_address)

    async def get_sync_status(self) -> SyncStatus:
        """Get inbox sync status.

        Returns:
            SyncStatus with email count and hash.
        """
        return await self._api_client.get_sync_status(self.email_address)

    async def wait_for_email(
        self,
        options: WaitForEmailOptions | None = None,
    ) -> Email:
        """Wait for an email matching the filter options.

        Args:
            options: Filter options for matching emails.

        Returns:
            The first Email matching the filter.

        Raises:
            TimeoutError: If no matching email arrives within the timeout.
        """
        options = options or WaitForEmailOptions()
        result_future: asyncio.Future[Email] = asyncio.get_running_loop().create_future()

        async def callback(email: Email) -> None:
            if result_future.done():
                return
            if matches_filter(email, options):
                result_future.set_result(email)

        subscription = await self.on_new_email(callback)

        try:
            # Check existing emails first
            existing_emails = await self.list_emails()
            for email in existing_emails:
                if matches_filter(email, options):
                    if not result_future.done():
                        result_future.set_result(email)
                    break

            # Wait for result with timeout
            result = await asyncio.wait_for(
                result_future,
                timeout=options.timeout / 1000,
            )
            return result

        except asyncio.TimeoutError:
            raise TimeoutError(f"Timeout waiting for email after {options.timeout}ms") from None
        finally:
            await self._strategy.unsubscribe(subscription)
            if subscription in self._subscriptions:
                self._subscriptions.remove(subscription)

    async def wait_for_email_count(
        self,
        count: int,
        options: WaitForCountOptions | None = None,
    ) -> list[Email]:
        """Wait until the inbox has at least the specified number of emails.

        Args:
            count: Minimum number of emails to wait for.
            options: Options including timeout in milliseconds.

        Returns:
            List of all emails in the inbox.

        Raises:
            TimeoutError: If the count is not reached within the timeout.
        """
        options = options or WaitForCountOptions()
        result_future: asyncio.Future[list[Email]] = asyncio.get_running_loop().create_future()

        async def check_count() -> None:
            if result_future.done():
                return
            emails = await self.list_emails()
            if len(emails) >= count and not result_future.done():
                result_future.set_result(emails)

        async def callback(email: Email) -> None:
            await check_count()

        subscription = await self.on_new_email(callback)

        try:
            # Check existing emails first
            await check_count()

            # Wait for result with timeout
            result = await asyncio.wait_for(
                result_future,
                timeout=options.timeout / 1000,
            )
            return result

        except asyncio.TimeoutError:
            # Get final count for error message
            emails = await self.list_emails()
            raise TimeoutError(
                f"Timeout waiting for {count} emails after {options.timeout}ms (got {len(emails)})"
            ) from None
        finally:
            await self._strategy.unsubscribe(subscription)
            if subscription in self._subscriptions:
                self._subscriptions.remove(subscription)

    async def on_new_email(
        self,
        callback: Callable[[Email], Any],
        *,
        mark_existing_seen: bool = True,
    ) -> Subscription:
        """Subscribe to new email notifications.

        Args:
            callback: Function to call when new emails arrive.
            mark_existing_seen: If True (default), existing emails won't trigger
                the callback. Set to False to receive callbacks for existing
                emails too.

        Returns:
            A Subscription for managing the subscription.
        """
        subscription = await self._strategy.subscribe(self, callback)

        if mark_existing_seen:
            existing_emails = await self.list_emails()
            for email in existing_emails:
                subscription.mark_seen(email.id)

        self._subscriptions.append(subscription)
        return subscription

    async def unsubscribe(self, subscription: Subscription) -> None:
        """Unsubscribe from email notifications.

        Args:
            subscription: The subscription to cancel (returned from on_new_email).
        """
        await self._strategy.unsubscribe(subscription)
        if subscription in self._subscriptions:
            self._subscriptions.remove(subscription)

    def export(self) -> ExportedInbox:
        """Export inbox data for persistence/sharing.

        Per VaultSandbox spec Section 9, exports include version, email address,
        expiration, inbox hash, and for encrypted inboxes: server public key and
        secret key (base64url encoded).

        Note: Public key is NOT exported as it can be derived from secret key
        at offset 1152 (see Section 4.2).

        WARNING: Exported data contains private keys. Handle securely.

        Returns:
            ExportedInbox with keypair and metadata.
        """
        # For encrypted inboxes, include cryptographic fields
        secret_key: str | None = None
        if self.encrypted and self._keypair is not None:
            secret_key = to_base64url(self._keypair.secret_key)

        return ExportedInbox(
            version=EXPORT_VERSION,
            email_address=self.email_address,
            expires_at=self.expires_at.isoformat().replace("+00:00", "Z"),
            inbox_hash=self.inbox_hash,
            encrypted=self.encrypted,
            email_auth=self.email_auth,
            exported_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            server_sig_pk=self.server_sig_pk,
            secret_key=secret_key,
        )

    # Webhook methods

    async def create_webhook(
        self,
        url: str,
        events: list[str],
        *,
        template: str | CustomTemplate | None = None,
        filter: FilterConfig | None = None,
        description: str | None = None,
        allow_http: bool = False,
    ) -> Webhook:
        """Create a webhook for this inbox.

        Webhooks are scoped to individual inboxes. Each webhook only receives
        events for the inbox it was created on. To receive notifications for
        multiple inboxes, create a webhook on each inbox separately.

        Webhooks allow you to receive real-time HTTP notifications when
        events occur in this inbox, such as new emails arriving.

        Args:
            url: Target URL for webhook deliveries (HTTPS required in production).
            events: Event types to subscribe to (e.g., ["email.received"]).
            template: Optional payload template name ("slack", "discord", etc.)
                or CustomTemplate for custom payloads.
            filter: Optional filter configuration to only receive matching events.
            description: Optional human-readable description (max 500 chars).
            allow_http: If True, allow HTTP URLs (insecure). Default is False.

        Returns:
            The created Webhook object including the signing secret.

        Raises:
            ValueError: If URL is invalid or events list is empty.
            WebhookLimitReachedError: If the webhook limit for this inbox is reached.

        Example:
            ```python
            webhook = await inbox.create_webhook(
                url="https://example.com/webhook",
                events=["email.received"],
                description="Notify when emails arrive"
            )
            print(f"Webhook created: {webhook.id}")
            print(f"Secret: {webhook.secret}")  # Save this for verification!
            ```
        """
        options = CreateWebhookOptions(
            url=url,
            events=events,
            template=template,
            filter=filter,
            description=description,
        )
        data = await self._api_client.create_inbox_webhook(
            self.email_address, options, allow_http=allow_http
        )
        return Webhook._from_data(data, self._api_client, self.email_address)

    async def list_webhooks(self) -> list[Webhook]:
        """List all webhooks for this inbox.

        Webhooks are scoped to individual inboxes. This method only returns
        webhooks created on this specific inbox.

        Note: The signing secret is not included in list responses.
        Use get_webhook() to retrieve a webhook with its secret.

        Returns:
            List of Webhook objects scoped to this inbox.
        """
        result = await self._api_client.list_inbox_webhooks(self.email_address)
        return [
            Webhook._from_data(w, self._api_client, self.email_address) for w in result.webhooks
        ]

    async def get_webhook(self, webhook_id: str) -> Webhook:
        """Get a specific webhook by ID.

        Args:
            webhook_id: The webhook ID (whk_ prefix).

        Returns:
            The Webhook object including secret and stats.

        Raises:
            WebhookNotFoundError: If the webhook is not found.
        """
        data = await self._api_client.get_inbox_webhook(self.email_address, webhook_id)
        return Webhook._from_data(data, self._api_client, self.email_address)

    async def delete_webhook(self, webhook_id: str) -> None:
        """Delete a webhook by ID.

        Args:
            webhook_id: The webhook ID (whk_ prefix).

        Raises:
            WebhookNotFoundError: If the webhook is not found.
        """
        await self._api_client.delete_inbox_webhook(self.email_address, webhook_id)

    # Chaos methods

    async def get_chaos(self) -> ChaosConfig:
        """Get the chaos configuration for this inbox.

        Chaos engineering allows controlled injection of failures and delays
        into email processing to test system resilience.

        Returns:
            ChaosConfig with current chaos settings.

        Raises:
            ApiError: If chaos is disabled globally on the server (403).

        Example:
            ```python
            chaos = await inbox.get_chaos()
            if chaos.enabled:
                print("Chaos is enabled")
                if chaos.latency and chaos.latency.enabled:
                    print(f"Latency: {chaos.latency.min_delay_ms}-{chaos.latency.max_delay_ms}ms")
            ```
        """
        return await self._api_client.get_inbox_chaos(self.email_address)

    async def set_chaos(
        self,
        *,
        enabled: bool,
        expires_at: str | None = None,
        latency: LatencyConfig | None = None,
        connection_drop: ConnectionDropConfig | None = None,
        random_error: RandomErrorConfig | None = None,
        greylist: GreylistConfig | None = None,
        blackhole: BlackholeConfig | None = None,
    ) -> ChaosConfig:
        """Set the chaos configuration for this inbox.

        Chaos engineering allows controlled injection of failures and delays
        into email processing to test system resilience.

        When multiple chaos types are enabled, they are evaluated in priority order
        (first match wins):
        1. Connection Drop (most disruptive)
        2. Greylisting
        3. Random Error
        4. Blackhole
        5. Latency (least disruptive)

        Args:
            enabled: Master switch for chaos on this inbox.
            expires_at: Auto-disable chaos after this timestamp (ISO 8601 format).
            latency: Latency injection settings.
            connection_drop: Connection drop settings.
            random_error: Random error settings.
            greylist: Greylisting settings.
            blackhole: Blackhole mode settings.

        Returns:
            ChaosConfig with the applied settings (including server defaults).

        Raises:
            ApiError: If chaos is disabled globally (403) or validation fails (400).

        Example:
            ```python
            # Enable latency injection with 50% probability
            chaos = await inbox.set_chaos(
                enabled=True,
                latency=LatencyConfig(
                    enabled=True,
                    min_delay_ms=1000,
                    max_delay_ms=5000,
                    probability=0.5,
                ),
            )

            # Enable random temporary errors
            chaos = await inbox.set_chaos(
                enabled=True,
                random_error=RandomErrorConfig(
                    enabled=True,
                    error_rate=0.2,
                    error_types=["temporary"],
                ),
            )

            # Enable greylisting simulation
            chaos = await inbox.set_chaos(
                enabled=True,
                greylist=GreylistConfig(
                    enabled=True,
                    max_attempts=3,
                ),
            )
            ```
        """
        config = ChaosConfig(
            enabled=enabled,
            expires_at=expires_at,
            latency=latency,
            connection_drop=connection_drop,
            random_error=random_error,
            greylist=greylist,
            blackhole=blackhole,
        )
        return await self._api_client.set_inbox_chaos(self.email_address, config)

    async def disable_chaos(self) -> None:
        """Disable all chaos for this inbox.

        This is equivalent to calling `set_chaos(enabled=False)` or
        making a DELETE request to the chaos endpoint.

        Raises:
            ApiError: If chaos is disabled globally (403) or other API errors.

        Example:
            ```python
            # Disable chaos after testing
            await inbox.disable_chaos()
            ```
        """
        await self._api_client.disable_inbox_chaos(self.email_address)
