"""HTTP API client with retry logic for VaultSandbox SDK."""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any, cast
from urllib.parse import quote

import httpx

from ..errors import ApiError, EmailNotFoundError, InboxNotFoundError, NetworkError
from ..types import (
    ClientConfig,
    EmailResponse,
    EncryptionPolicy,
    InboxData,
    InboxEncryptionMode,
    RawEmailResponse,
    ServerInfo,
    SyncStatus,
)

# More robust patterns for error classification
_INBOX_NOT_FOUND_PATTERN = re.compile(r"\binbox\b.*\b(not found|does not exist)\b", re.IGNORECASE)
_EMAIL_NOT_FOUND_PATTERN = re.compile(r"\bemail\b.*\b(not found|does not exist)\b", re.IGNORECASE)


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
            ApiError: For other API errors.
        """
        try:
            data = response.json()
            message = data.get("message", data.get("error", response.text))
        except (ValueError, json.JSONDecodeError):
            message = response.text or f"HTTP {response.status_code}"

        if response.status_code == 404:
            if _INBOX_NOT_FOUND_PATTERN.search(message):
                raise InboxNotFoundError(message)
            if _EMAIL_NOT_FOUND_PATTERN.search(message):
                raise EmailNotFoundError(message)
            # Default to inbox not found for 404
            raise InboxNotFoundError(message)

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
