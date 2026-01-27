"""Email API client for VaultSandbox SDK."""

from __future__ import annotations

from typing import cast

from ..types import EmailResponse, RawEmailResponse
from .base_client import BaseApiClient, encode_path_segment


class EmailApiClient(BaseApiClient):
    """API client for email operations.

    Provides methods for listing, retrieving, and managing emails within inboxes.
    """

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
        encoded = encode_path_segment(email_address)
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
        encoded_addr = encode_path_segment(email_address)
        encoded_id = encode_path_segment(email_id)
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
        encoded_addr = encode_path_segment(email_address)
        encoded_id = encode_path_segment(email_id)
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
        encoded_addr = encode_path_segment(email_address)
        encoded_id = encode_path_segment(email_id)
        await self._request("PATCH", f"/api/inboxes/{encoded_addr}/emails/{encoded_id}/read")

    async def delete_email(self, email_address: str, email_id: str) -> None:
        """Delete an email.

        Args:
            email_address: The email address of the inbox.
            email_id: The email ID.
        """
        encoded_addr = encode_path_segment(email_address)
        encoded_id = encode_path_segment(email_id)
        await self._request("DELETE", f"/api/inboxes/{encoded_addr}/emails/{encoded_id}")
