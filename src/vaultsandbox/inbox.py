"""Inbox class for VaultSandbox SDK."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from .crypto import Keypair, to_base64
from .email import Email
from .errors import TimeoutError
from .strategies import Subscription
from .types import (
    ExportedInbox,
    SyncStatus,
    WaitForCountOptions,
    WaitForEmailOptions,
)
from .utils.email_utils import matches_filter

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
        inbox_hash: SHA-256 hash of the client KEM public key.
        server_sig_pk: Server signing public key for verification.
    """

    email_address: str
    expires_at: datetime
    inbox_hash: str
    server_sig_pk: str
    _keypair: Keypair = field(repr=False)
    _api_client: ApiClient = field(repr=False)
    _strategy: DeliveryStrategy = field(repr=False)
    _subscriptions: list[Subscription] = field(default_factory=list, repr=False)

    async def list_emails(self) -> list[Email]:
        """List all emails in the inbox.

        Returns:
            List of Email objects.
        """
        list_responses = await self._api_client.list_emails(self.email_address)
        emails = []
        for email_data in list_responses:
            # Check if full encrypted content is present; if not, fetch it
            if not email_data.get("encryptedParsed"):
                email_data = await self._api_client.get_email(self.email_address, email_data["id"])
            emails.append(Email._from_response(email_data, self))
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
        """
        from .crypto import decrypt_raw
        from .types import RawEmail

        raw_response = await self._api_client.get_raw_email(self.email_address, email_id)
        raw = decrypt_raw(raw_response["encryptedRaw"], self._keypair)
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
        """
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

        WARNING: Exported data contains private keys. Handle securely.

        Returns:
            ExportedInbox with keypair and metadata.
        """
        return ExportedInbox(
            email_address=self.email_address,
            expires_at=self.expires_at.isoformat().replace("+00:00", "Z"),
            inbox_hash=self.inbox_hash,
            server_sig_pk=self.server_sig_pk,
            public_key_b64=to_base64(self._keypair.public_key),
            secret_key_b64=to_base64(self._keypair.secret_key),
            exported_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )
