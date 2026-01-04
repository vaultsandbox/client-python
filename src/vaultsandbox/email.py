"""Email class for VaultSandbox SDK."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from .types import Attachment, AuthResults, EmailResponse
from .utils import parse_iso_timestamp
from .utils.email_utils import decrypt_email_response

if TYPE_CHECKING:
    from .inbox import Inbox
    from .types import RawEmail


@dataclass
class Email:
    """Represents a decrypted email.

    Attributes:
        id: Unique email identifier.
        from_address: Sender email address.
        to: List of recipient email addresses.
        subject: Email subject line.
        received_at: Timestamp when the email was received.
        is_read: Whether the email has been read.
        text: Plain text content (may be None).
        html: HTML content (may be None).
        headers: Email headers dictionary.
        attachments: List of attachments.
        links: List of links found in the email.
        auth_results: Email authentication results (SPF/DKIM/DMARC/ReverseDNS).
        metadata: Raw decrypted metadata (from encryptedMetadata).
        parsed_metadata: Additional metadata from parsed content (from encryptedParsed).
    """

    id: str
    from_address: str
    to: list[str]
    subject: str
    received_at: datetime
    is_read: bool
    text: str | None
    html: str | None
    headers: dict[str, str]
    attachments: list[Attachment]
    links: list[str]
    auth_results: AuthResults
    metadata: dict[str, Any]
    parsed_metadata: dict[str, Any]
    _inbox: Inbox = field(repr=False)

    @classmethod
    def _from_response(cls, response: EmailResponse, inbox: Inbox) -> Email:
        """Create an Email instance from an encrypted response.

        Args:
            response: The encrypted email response from the server.
            inbox: The inbox this email belongs to.

        Returns:
            A new Email instance with decrypted content.
        """
        # Pass pinned server key for validation per Section 8.1 step 5
        decrypted = decrypt_email_response(
            response,
            inbox._keypair,
            pinned_server_key=inbox.server_sig_pk,
        )

        # Parse received_at timestamp
        received_at = parse_iso_timestamp(decrypted["received_at"])

        return cls(
            id=decrypted["id"],
            from_address=decrypted["from_address"],
            to=decrypted["to"],
            subject=decrypted["subject"],
            received_at=received_at,
            is_read=decrypted["is_read"],
            text=decrypted["text"],
            html=decrypted["html"],
            headers=decrypted["headers"],
            attachments=decrypted["attachments"],
            links=decrypted["links"],
            auth_results=decrypted["auth_results"],
            metadata=decrypted["metadata"],
            parsed_metadata=decrypted["parsed_metadata"],
            _inbox=inbox,
        )

    async def mark_as_read(self) -> None:
        """Mark this email as read."""
        await self._inbox._api_client.mark_email_as_read(self._inbox.email_address, self.id)
        self.is_read = True

    async def delete(self) -> None:
        """Delete this email."""
        await self._inbox._api_client.delete_email(self._inbox.email_address, self.id)

    async def get_raw(self) -> RawEmail:
        """Get the raw email source.

        Returns:
            RawEmail object with id and raw MIME content.
        """
        return await self._inbox.get_raw_email(self.id)
