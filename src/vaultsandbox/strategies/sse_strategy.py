"""SSE (Server-Sent Events) delivery strategy for VaultSandbox SDK."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from typing import TYPE_CHECKING

import httpx
from httpx_sse import aconnect_sse

from ..errors import SSEError
from ..types import SSEConfig
from .delivery_strategy import DeliveryStrategy, EmailCallback, Subscription

logger = logging.getLogger("vaultsandbox")

if TYPE_CHECKING:
    from ..http import ApiClient
    from ..inbox import Inbox


class SSEStrategy(DeliveryStrategy):
    """Server-Sent Events delivery strategy for real-time email notifications.

    This strategy maintains a persistent connection to the server and receives
    email notifications in real-time via SSE.
    """

    def __init__(
        self,
        api_client: ApiClient,
        config: SSEConfig | None = None,
    ) -> None:
        """Initialize the SSE strategy.

        Args:
            api_client: The API client for making requests.
            config: SSE configuration options.
        """
        self._api_client = api_client
        self._config = config or SSEConfig()
        self._subscriptions: dict[str, Subscription] = {}
        self._inbox_hash_map: dict[str, str] = {}  # inbox_hash -> email_address
        self._sse_task: asyncio.Task[None] | None = None
        self._running = True
        self._reconnect_count = 0
        self._client: httpx.AsyncClient | None = None
        self._connected_event: asyncio.Event | None = None
        self._error: BaseException | None = None

    async def subscribe(
        self,
        inbox: Inbox,
        callback: EmailCallback,
    ) -> Subscription:
        """Subscribe to new emails for an inbox.

        Args:
            inbox: The inbox to subscribe to.
            callback: Function to call when new emails arrive.

        Returns:
            A Subscription instance.

        Raises:
            SSEError: If the SSE connection fails or times out.
        """
        subscription = Subscription(inbox=inbox, callback=callback)

        # Track existing subscriptions before adding new one (for sync after reconnect)
        existing_subscriptions = list(self._subscriptions.values())

        self._subscriptions[inbox.email_address] = subscription
        self._inbox_hash_map[inbox.inbox_hash] = inbox.email_address

        # Reconnect SSE to include new inbox and wait for connection
        await self._reconnect_sse()

        # Wait for SSE connection to be established (with timeout)
        if self._connected_event:
            try:
                await asyncio.wait_for(self._connected_event.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                # Clean up the failed subscription
                del self._subscriptions[inbox.email_address]
                del self._inbox_hash_map[inbox.inbox_hash]
                raise SSEError("SSE connection timed out") from None

            # Check if the task failed during connection attempt
            if self._error is not None:
                # Clean up the failed subscription
                del self._subscriptions[inbox.email_address]
                del self._inbox_hash_map[inbox.inbox_hash]
                raise self._error

        # Sync existing subscriptions to catch emails during SSE disconnect window
        # Per plan-sync.md: after reconnecting SSE, sync all inboxes to catch missed emails
        if existing_subscriptions:
            await self._sync_subscriptions(existing_subscriptions)

        return subscription

    async def unsubscribe(self, subscription: Subscription) -> None:
        """Unsubscribe from new emails.

        Args:
            subscription: The subscription to cancel.
        """
        email_address = subscription.inbox.email_address
        inbox_hash = subscription.inbox.inbox_hash

        # Remove subscription
        if email_address in self._subscriptions:
            del self._subscriptions[email_address]
        if inbox_hash in self._inbox_hash_map:
            del self._inbox_hash_map[inbox_hash]

        # Reconnect SSE without this inbox (or close if no subscriptions)
        if self._subscriptions:
            # Track remaining subscriptions for sync after reconnect
            remaining_subscriptions = list(self._subscriptions.values())
            await self._reconnect_sse()

            # Wait for SSE connection before syncing
            if self._connected_event:
                try:
                    await asyncio.wait_for(self._connected_event.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    logger.debug("SSE reconnection timed out during unsubscribe")

            # Sync remaining subscriptions to catch emails during disconnect
            if remaining_subscriptions:
                await self._sync_subscriptions(remaining_subscriptions)
        else:
            await self._close_sse()

    async def close(self) -> None:
        """Close the strategy and clean up resources."""
        self._running = False
        await self._close_sse()
        self._subscriptions.clear()
        self._inbox_hash_map.clear()

    async def _close_sse(self) -> None:
        """Close the SSE connection."""
        if self._sse_task is not None:
            self._sse_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._sse_task
            self._sse_task = None

        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _reconnect_sse(self) -> None:
        """Reconnect the SSE connection with updated subscriptions."""
        await self._close_sse()

        if not self._subscriptions:
            return

        # Reset error state and create event to signal when connected
        self._error = None
        self._connected_event = asyncio.Event()
        self._sse_task = asyncio.create_task(self._run_sse())
        self._sse_task.add_done_callback(self._on_sse_task_done)

    def _on_sse_task_done(self, task: asyncio.Task[None]) -> None:
        """Handle SSE task completion and observe any exceptions.

        Args:
            task: The completed SSE task.
        """
        if task.cancelled():
            return

        exc = task.exception()
        if exc is not None:
            self._error = exc
            # Invoke the error callback if configured
            if self._config.on_error is not None:
                try:
                    self._config.on_error(exc)
                except Exception as callback_error:
                    logger.debug("Error in SSE error callback: %s", callback_error, exc_info=True)

    async def _run_sse(self) -> None:
        """Run the SSE connection loop with reconnection logic."""
        while self._running and self._subscriptions:
            try:
                await self._connect_and_listen()
                self._reconnect_count = 0  # Reset on successful connection
            except asyncio.CancelledError:
                break
            except Exception as e:
                self._reconnect_count += 1
                if self._reconnect_count >= self._config.max_reconnect_attempts:
                    raise SSEError(
                        f"Max reconnection attempts ({self._config.max_reconnect_attempts}) exceeded"
                    ) from e

                # Exponential backoff for reconnection
                delay = self._config.reconnect_interval * (2 ** (self._reconnect_count - 1))
                await asyncio.sleep(delay / 1000)

    async def _connect_and_listen(self) -> None:
        """Connect to SSE and listen for events."""
        if not self._subscriptions:
            return

        # Build inbox hashes query parameter
        inbox_hashes = ",".join(self._inbox_hash_map.keys())

        # Create HTTP client for SSE
        self._client = httpx.AsyncClient(
            base_url=self._api_client.config.base_url,
            headers={
                "X-API-Key": self._api_client.config.api_key,
                "Accept": "text/event-stream",
            },
            timeout=httpx.Timeout(None),  # No timeout for SSE
        )

        url = f"/api/events?inboxes={inbox_hashes}"

        async with aconnect_sse(self._client, "GET", url) as event_source:
            # Signal that we're connected
            if self._connected_event:
                self._connected_event.set()

            async for event in event_source.aiter_sse():
                if not self._running:
                    break

                if event.data:
                    await self._handle_event(event.data)

    async def _handle_event(self, data: str) -> None:
        """Handle an SSE event.

        Args:
            data: The event data as JSON string.
        """
        try:
            event_data = json.loads(data)
            inbox_id = event_data.get("inboxId")
            email_id = event_data.get("emailId")

            if not inbox_id or not email_id:
                return

            # Find the subscription for this inbox
            email_address = self._inbox_hash_map.get(inbox_id)
            if not email_address:
                return

            subscription = self._subscriptions.get(email_address)
            if not subscription:
                return

            # Skip already seen emails
            if subscription.has_seen(email_id):
                return

            subscription.mark_seen(email_id)

            # Fetch full email data and decrypt
            inbox = subscription.inbox
            email_response = await self._api_client.get_email(email_address, email_id)

            from ..email import Email

            email = Email._from_response(email_response, inbox)

            # Call callback (handle both sync and async)
            result = subscription.callback(email)
            if asyncio.iscoroutine(result):
                await result

        except json.JSONDecodeError as e:
            logger.debug("Failed to parse SSE event as JSON: %s", e)
        except Exception as e:
            logger.debug("Error handling SSE event: %s", e, exc_info=True)

    async def _sync_subscriptions(self, subscriptions: list[Subscription]) -> None:
        """Sync subscriptions to catch emails during SSE disconnect window.

        Per plan-sync.md: after SSE reconnection, we must check for emails
        that arrived during the disconnect window. This uses the hash-based
        sync approach - fetch email list and process any unseen emails.

        Args:
            subscriptions: List of subscriptions to sync.
        """
        # Sync all subscriptions in parallel for efficiency
        await asyncio.gather(
            *[self._sync_subscription(sub) for sub in subscriptions],
            return_exceptions=True,
        )

    async def _sync_subscription(self, subscription: Subscription) -> None:
        """Sync a single subscription to catch missed emails.

        Args:
            subscription: The subscription to sync.
        """
        inbox = subscription.inbox

        try:
            # Get list of emails from server (metadata only for efficiency)
            emails_response = await self._api_client.list_emails(
                inbox.email_address, include_content=False
            )

            # Process emails we haven't seen yet
            for email_data in emails_response:
                email_id = email_data["id"]

                # Skip already seen emails (deduplication)
                if subscription.has_seen(email_id):
                    continue

                subscription.mark_seen(email_id)

                # Fetch full email and fire callback
                try:
                    email_response = await self._api_client.get_email(inbox.email_address, email_id)

                    from ..email import Email

                    email = Email._from_response(email_response, inbox)

                    # Call callback (handle both sync and async)
                    result = subscription.callback(email)
                    if asyncio.iscoroutine(result):
                        await result

                except Exception as e:
                    logger.debug(
                        "Error fetching/processing email %s during sync: %s",
                        email_id,
                        e,
                    )

        except Exception as e:
            logger.debug(
                "Error syncing subscription for %s: %s",
                inbox.email_address,
                e,
                exc_info=True,
            )
