"""Base HTTP client with retry logic for VaultSandbox SDK."""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any, cast
from urllib.parse import quote

import httpx

from ..errors import (
    ApiError,
    EmailNotFoundError,
    InboxNotFoundError,
    NetworkError,
    WebhookLimitReachedError,
    WebhookNotFoundError,
)
from ..types import ClientConfig, EncryptionPolicy, ServerInfo

# More robust patterns for error classification
_INBOX_NOT_FOUND_PATTERN = re.compile(r"\binbox\b.*\b(not found|does not exist)\b", re.IGNORECASE)
_EMAIL_NOT_FOUND_PATTERN = re.compile(r"\bemail\b.*\b(not found|does not exist)\b", re.IGNORECASE)
_WEBHOOK_NOT_FOUND_PATTERN = re.compile(
    r"\bwebhook\b.*\b(not found|does not exist)\b", re.IGNORECASE
)
_WEBHOOK_LIMIT_PATTERN = re.compile(r"\bwebhook\b.*\blimit\b", re.IGNORECASE)


def encode_path_segment(value: str) -> str:
    """URL-encode a path segment for use in API URLs.

    Args:
        value: The value to encode.

    Returns:
        URL-encoded string safe for use in URL paths.
    """
    return quote(value, safe="")


class BaseApiClient:
    """Base HTTP client for VaultSandbox API with automatic retry logic.

    Provides common HTTP operations used by all domain-specific clients.

    Attributes:
        config: Client configuration.
    """

    def __init__(self, config: ClientConfig) -> None:
        """Initialize the base API client.

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
            WebhookNotFoundError: If the webhook is not found.
            WebhookLimitReachedError: If the webhook limit is reached.
            ApiError: For other API errors.
        """
        try:
            data = response.json()
            message = data.get("message", data.get("error", response.text))
        except (ValueError, json.JSONDecodeError):
            message = response.text or f"HTTP {response.status_code}"

        if response.status_code == 404:
            if _WEBHOOK_NOT_FOUND_PATTERN.search(message):
                raise WebhookNotFoundError(message)
            if _INBOX_NOT_FOUND_PATTERN.search(message):
                raise InboxNotFoundError(message)
            if _EMAIL_NOT_FOUND_PATTERN.search(message):
                raise EmailNotFoundError(message)
            # Default to inbox not found for 404
            raise InboxNotFoundError(message)

        if response.status_code == 409 and _WEBHOOK_LIMIT_PATTERN.search(message):
            raise WebhookLimitReachedError(message)

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
            spam_analysis_enabled=data.get("spamAnalysisEnabled", False),
            chaos_enabled=data.get("chaosEnabled", False),
        )
