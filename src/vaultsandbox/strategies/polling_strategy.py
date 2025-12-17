"""Polling delivery strategy for VaultSandbox SDK."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
from typing import TYPE_CHECKING

from ..types import PollingConfig
from .delivery_strategy import DeliveryStrategy, EmailCallback, Subscription

logger = logging.getLogger("vaultsandbox")

if TYPE_CHECKING:
    from ..http import ApiClient
    from ..inbox import Inbox


class PollingStrategy(DeliveryStrategy):
    """Polling-based delivery strategy with exponential backoff.

    This strategy polls the server for new emails using smart change detection.
    It uses the sync status hash to detect changes before fetching full email lists.
    """

    def __init__(
        self,
        api_client: ApiClient,
        config: PollingConfig | None = None,
    ) -> None:
        """Initialize the polling strategy.

        Args:
            api_client: The API client for making requests.
            config: Polling configuration options.
        """
        self._api_client = api_client
        self._config = config or PollingConfig()
        self._subscriptions: dict[str, Subscription] = {}
        self._polling_tasks: dict[str, asyncio.Task[None]] = {}
        self._running = True

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
        """
        subscription = Subscription(inbox=inbox, callback=callback)
        self._subscriptions[inbox.email_address] = subscription

        # Start polling task for this inbox
        task = asyncio.create_task(self._poll_inbox(subscription))
        self._polling_tasks[inbox.email_address] = task

        return subscription

    async def unsubscribe(self, subscription: Subscription) -> None:
        """Unsubscribe from new emails.

        Args:
            subscription: The subscription to cancel.
        """
        email_address = subscription.inbox.email_address

        # Cancel polling task
        if email_address in self._polling_tasks:
            self._polling_tasks[email_address].cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._polling_tasks[email_address]
            del self._polling_tasks[email_address]

        # Remove subscription
        if email_address in self._subscriptions:
            del self._subscriptions[email_address]

    async def close(self) -> None:
        """Close the strategy and cancel all polling tasks."""
        self._running = False

        # Cancel all polling tasks
        for task in self._polling_tasks.values():
            task.cancel()

        # Wait for all tasks to complete
        if self._polling_tasks:
            await asyncio.gather(*self._polling_tasks.values(), return_exceptions=True)

        self._polling_tasks.clear()
        self._subscriptions.clear()

    async def _poll_inbox(self, subscription: Subscription) -> None:
        """Poll an inbox for new emails.

        Args:
            subscription: The subscription to poll for.
        """
        inbox = subscription.inbox
        last_hash: str | None = None
        current_backoff: float = self._config.initial_interval

        while self._running:
            try:
                # Get sync status (lightweight check)
                sync_status = await self._api_client.get_sync_status(inbox.email_address)

                # Check if emails have changed
                if last_hash != sync_status.emails_hash:
                    last_hash = sync_status.emails_hash
                    current_backoff = self._config.initial_interval  # Reset on change

                    # Fetch and process new emails
                    await self._process_new_emails(subscription)
                else:
                    # Exponential backoff when no changes
                    current_backoff = min(
                        current_backoff * self._config.backoff_multiplier,
                        self._config.max_backoff,
                    )

                # Add jitter to prevent thundering herd
                jitter = random.random() * self._config.jitter_factor * current_backoff
                await asyncio.sleep((current_backoff + jitter) / 1000)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning("Error polling inbox %s: %s", inbox.email_address, e, exc_info=True)
                # Increase backoff on errors
                current_backoff = min(
                    current_backoff * self._config.backoff_multiplier,
                    self._config.max_backoff,
                )
                await asyncio.sleep(current_backoff / 1000)

    async def _process_new_emails(self, subscription: Subscription) -> None:
        """Process new emails for a subscription.

        Args:
            subscription: The subscription to process emails for.
        """
        inbox = subscription.inbox

        # Fetch all emails
        email_responses = await self._api_client.list_emails(inbox.email_address)

        for email_response in email_responses:
            email_id = email_response["id"]

            # Skip already seen emails
            if subscription.has_seen(email_id):
                continue

            subscription.mark_seen(email_id)

            try:
                # Decrypt and create Email object
                from ..email import Email

                email = Email._from_response(email_response, inbox)

                # Call callback (handle both sync and async)
                result = subscription.callback(email)
                if asyncio.iscoroutine(result):
                    await result

            except Exception as e:
                logger.debug("Error processing email %s: %s", email_id, e, exc_info=True)
