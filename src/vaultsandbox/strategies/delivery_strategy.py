"""Abstract delivery strategy interface for VaultSandbox SDK."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..email import Email
    from ..inbox import Inbox

# Type alias for email callbacks
EmailCallback = Callable[["Email"], Any]


@dataclass
class Subscription:
    """Represents a subscription to new emails for an inbox.

    Attributes:
        inbox: The inbox being subscribed to.
        callback: Function to call when new emails arrive.
        seen_email_ids: Set of email IDs already processed.
    """

    inbox: Inbox
    callback: EmailCallback
    seen_email_ids: set[str] = field(default_factory=set)

    def has_seen(self, email_id: str) -> bool:
        """Check if an email has already been processed.

        Args:
            email_id: The email ID to check.

        Returns:
            True if the email has been seen.
        """
        return email_id in self.seen_email_ids

    def mark_seen(self, email_id: str) -> None:
        """Mark an email as processed.

        Args:
            email_id: The email ID to mark.
        """
        self.seen_email_ids.add(email_id)


class DeliveryStrategy(ABC):
    """Abstract base class for email delivery strategies."""

    @abstractmethod
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
            A Subscription instance for managing the subscription.
        """
        pass  # pragma: no cover

    @abstractmethod
    async def unsubscribe(self, subscription: Subscription) -> None:
        """Unsubscribe from new emails.

        Args:
            subscription: The subscription to cancel.
        """
        pass  # pragma: no cover

    @abstractmethod
    async def close(self) -> None:
        """Close the strategy and clean up resources."""
        pass  # pragma: no cover
