"""HTTP API client with retry logic for VaultSandbox SDK.

This module provides the main ApiClient class which composes multiple
domain-specific API clients:
- BaseApiClient: Common HTTP operations and server endpoints
- InboxApiClient: Inbox CRUD operations
- EmailApiClient: Email operations
- WebhookApiClient: Webhook operations
- ChaosApiClient: Chaos configuration operations

For new code, consider using the domain-specific clients directly for
better separation of concerns.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import httpx

from ..types import (
    BlackholeConfig,
    ChaosConfig,
    ClientConfig,
    ConnectionDropConfig,
    CreateWebhookOptions,
    CustomTemplate,
    EmailResponse,
    FilterConfig,
    FilterRule,
    GreylistConfig,
    InboxData,
    InboxEncryptionMode,
    LatencyConfig,
    RandomErrorConfig,
    RawEmailResponse,
    RotateSecretResult,
    ServerInfo,
    SyncStatus,
    TestWebhookResult,
    UpdateWebhookOptions,
    WebhookData,
    WebhookListData,
    WebhookStats,
)

# Re-export the domain-specific clients for direct use
from .base_client import BaseApiClient, encode_path_segment
from .chaos_client import ChaosApiClient
from .email_client import EmailApiClient
from .inbox_client import InboxApiClient
from .webhook_client import WebhookApiClient, validate_webhook_url

# Backward compatibility alias
_encode_path_segment = encode_path_segment
_validate_webhook_url = validate_webhook_url

__all__ = [
    "ApiClient",
    "BaseApiClient",
    "ChaosApiClient",
    "EmailApiClient",
    "InboxApiClient",
    "WebhookApiClient",
    "encode_path_segment",
    "validate_webhook_url",
]


class ApiClient:
    """HTTP client for VaultSandbox API with automatic retry logic.

    This class provides a unified interface to all API operations by
    composing multiple domain-specific clients. For new code, you may
    use the individual clients (InboxApiClient, EmailApiClient, etc.)
    directly for better modularity.

    Attributes:
        config: Client configuration.
    """

    def __init__(self, config: ClientConfig) -> None:
        """Initialize the API client.

        Args:
            config: Client configuration with API key and settings.
        """
        self.config = config

        # Initialize domain-specific clients
        self._base = BaseApiClient(config)
        self._inbox = InboxApiClient(config)
        self._email = EmailApiClient(config)
        self._webhook = WebhookApiClient(config)
        self._chaos = ChaosApiClient(config)

        # Wire up cross-client dependencies
        self._inbox._chaos_client = self._chaos

    # Expose internal client reference for strategies that need direct HTTP client access
    @property
    def _client(self) -> httpx.AsyncClient | None:
        """Access the underlying httpx client (for internal use)."""
        return self._base._client

    @_client.setter
    def _client(self, value: httpx.AsyncClient | None) -> None:
        """Set the underlying httpx client (for testing)."""
        self._base._client = value
        self._inbox._client = value
        self._email._client = value
        self._webhook._client = value
        self._chaos._client = value

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client (for internal use)."""
        return await self._base._get_client()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """Make an HTTP request with retry logic (for internal use)."""
        return await self._base._request(method, path, json=json, params=params)

    async def close(self) -> None:
        """Close the HTTP client."""
        # Only need to close one since they share config but have separate clients
        await self._base.close()
        await self._inbox.close()
        await self._email.close()
        await self._webhook.close()
        await self._chaos.close()

    # Server endpoints (delegated to base client)

    async def check_key(self) -> bool:
        """Validate the API key.

        Returns:
            True if the API key is valid.
        """
        return await self._base.check_key()

    async def get_server_info(self) -> ServerInfo:
        """Get server information and capabilities.

        Returns:
            ServerInfo with cryptographic configuration.
        """
        return await self._base.get_server_info()

    # Inbox endpoints (delegated to inbox client)

    async def create_inbox(
        self,
        client_kem_pk: str | None = None,
        *,
        ttl: int | None = None,
        email_address: str | None = None,
        email_auth: bool | None = None,
        encryption: InboxEncryptionMode | None = None,
        spam_analysis: bool | None = None,
        chaos: ChaosConfig | None = None,
    ) -> InboxData:
        """Create a new inbox.

        Args:
            client_kem_pk: Base64url-encoded ML-KEM-768 public key.
                Required for encrypted inboxes, omit for plain inboxes.
            ttl: Time-to-live in seconds.
            email_address: Desired email address or domain.
            email_auth: Enable/disable email authentication checks. None uses server default.
            encryption: Encryption mode ('encrypted' or 'plain'). None uses server default.
            spam_analysis: Enable/disable spam analysis. None uses server default.
            chaos: Initial chaos configuration. Requires chaos to be enabled globally.

        Returns:
            InboxData with the created inbox information.
        """
        return await self._inbox.create_inbox(
            client_kem_pk,
            ttl=ttl,
            email_address=email_address,
            email_auth=email_auth,
            encryption=encryption,
            spam_analysis=spam_analysis,
            chaos=chaos,
        )

    async def delete_inbox(self, email_address: str) -> None:
        """Delete a specific inbox.

        Args:
            email_address: The email address of the inbox to delete.
        """
        await self._inbox.delete_inbox(email_address)

    async def delete_all_inboxes(self) -> int:  # pragma: no cover
        """Delete all inboxes for the API key.

        Note: Not tested in integration tests as it would interfere with
        concurrent test runs by deleting all inboxes for the API key.

        Returns:
            Number of inboxes deleted.
        """
        return await self._inbox.delete_all_inboxes()

    async def get_sync_status(self, email_address: str) -> SyncStatus:
        """Get inbox sync status.

        Args:
            email_address: The email address of the inbox.

        Returns:
            SyncStatus with email count and hash.
        """
        return await self._inbox.get_sync_status(email_address)

    # Email endpoints (delegated to email client)

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
        return await self._email.list_emails(email_address, include_content)

    async def get_email(self, email_address: str, email_id: str) -> EmailResponse:
        """Get a specific email.

        Args:
            email_address: The email address of the inbox.
            email_id: The email ID.

        Returns:
            Encrypted email response.
        """
        return await self._email.get_email(email_address, email_id)

    async def get_raw_email(self, email_address: str, email_id: str) -> RawEmailResponse:
        """Get raw email source.

        Args:
            email_address: The email address of the inbox.
            email_id: The email ID.

        Returns:
            Raw email response with encrypted content.
        """
        return await self._email.get_raw_email(email_address, email_id)

    async def mark_email_as_read(self, email_address: str, email_id: str) -> None:
        """Mark an email as read.

        Args:
            email_address: The email address of the inbox.
            email_id: The email ID.
        """
        await self._email.mark_email_as_read(email_address, email_id)

    async def delete_email(self, email_address: str, email_id: str) -> None:
        """Delete an email.

        Args:
            email_address: The email address of the inbox.
            email_id: The email ID.
        """
        await self._email.delete_email(email_address, email_id)

    # Webhook endpoints (delegated to webhook client)

    # Expose serialization/parsing methods for backward compatibility
    def _serialize_filter_rule(self, rule: FilterRule) -> dict[str, Any]:
        """Serialize a FilterRule to API format."""
        return self._webhook._serialize_filter_rule(rule)

    def _serialize_filter_config(self, filter_config: FilterConfig) -> dict[str, Any]:
        """Serialize a FilterConfig to API format."""
        return self._webhook._serialize_filter_config(filter_config)

    def _serialize_template(self, template: str | CustomTemplate) -> str | dict[str, Any]:
        """Serialize a template to API format."""
        return self._webhook._serialize_template(template)

    def _parse_filter_config(self, data: dict[str, Any]) -> FilterConfig:
        """Parse filter config from API response."""
        return self._webhook._parse_filter_config(data)

    def _parse_template(self, data: Any) -> str | CustomTemplate | None:
        """Parse template from API response."""
        return self._webhook._parse_template(data)

    def _parse_webhook_stats(self, data: dict[str, Any] | None) -> WebhookStats | None:
        """Parse webhook stats from API response."""
        return self._webhook._parse_webhook_stats(data)

    def _parse_webhook_data(self, data: dict[str, Any]) -> WebhookData:
        """Parse WebhookData from API response."""
        return self._webhook._parse_webhook_data(data)

    async def create_inbox_webhook(
        self,
        email_address: str,
        options: CreateWebhookOptions,
        *,
        allow_http: bool = False,
    ) -> WebhookData:
        """Create a webhook for an inbox.

        Args:
            email_address: The email address of the inbox.
            options: Webhook creation options.
            allow_http: If True, allow HTTP URLs. Default is False (HTTPS only).

        Returns:
            WebhookData with the created webhook information including secret.

        Raises:
            ValueError: If webhook URL is invalid or events list is empty.
        """
        return await self._webhook.create_inbox_webhook(
            email_address, options, allow_http=allow_http
        )

    async def list_inbox_webhooks(self, email_address: str) -> WebhookListData:
        """List all webhooks for an inbox.

        Args:
            email_address: The email address of the inbox.

        Returns:
            WebhookListData with list of webhooks and total count.
        """
        return await self._webhook.list_inbox_webhooks(email_address)

    async def get_inbox_webhook(self, email_address: str, webhook_id: str) -> WebhookData:
        """Get a specific webhook for an inbox.

        Args:
            email_address: The email address of the inbox.
            webhook_id: The webhook ID.

        Returns:
            WebhookData with webhook information including secret and stats.
        """
        return await self._webhook.get_inbox_webhook(email_address, webhook_id)

    async def update_inbox_webhook(
        self,
        email_address: str,
        webhook_id: str,
        options: UpdateWebhookOptions,
        *,
        allow_http: bool = False,
    ) -> WebhookData:
        """Update a webhook for an inbox.

        Args:
            email_address: The email address of the inbox.
            webhook_id: The webhook ID.
            options: Update options.
            allow_http: If True, allow HTTP URLs. Default is False (HTTPS only).

        Returns:
            WebhookData with updated webhook information.

        Raises:
            ValueError: If webhook URL is invalid.
        """
        return await self._webhook.update_inbox_webhook(
            email_address, webhook_id, options, allow_http=allow_http
        )

    async def delete_inbox_webhook(self, email_address: str, webhook_id: str) -> None:
        """Delete a webhook for an inbox.

        Args:
            email_address: The email address of the inbox.
            webhook_id: The webhook ID.
        """
        await self._webhook.delete_inbox_webhook(email_address, webhook_id)

    async def test_inbox_webhook(self, email_address: str, webhook_id: str) -> TestWebhookResult:
        """Test a webhook for an inbox by sending a test event.

        Args:
            email_address: The email address of the inbox.
            webhook_id: The webhook ID.

        Returns:
            TestWebhookResult with test results.
        """
        return await self._webhook.test_inbox_webhook(email_address, webhook_id)

    async def rotate_inbox_webhook_secret(
        self, email_address: str, webhook_id: str
    ) -> RotateSecretResult:
        """Rotate the signing secret for an inbox webhook.

        Args:
            email_address: The email address of the inbox.
            webhook_id: The webhook ID.

        Returns:
            RotateSecretResult with new secret and grace period info.
        """
        return await self._webhook.rotate_inbox_webhook_secret(email_address, webhook_id)

    # Chaos configuration endpoints (delegated to chaos client)

    # Expose serialization/parsing methods for backward compatibility
    def _serialize_latency_config(self, config: LatencyConfig) -> dict[str, Any]:
        """Serialize a LatencyConfig to API format."""
        return self._chaos._serialize_latency_config(config)

    def _serialize_connection_drop_config(self, config: ConnectionDropConfig) -> dict[str, Any]:
        """Serialize a ConnectionDropConfig to API format."""
        return self._chaos._serialize_connection_drop_config(config)

    def _serialize_random_error_config(self, config: RandomErrorConfig) -> dict[str, Any]:
        """Serialize a RandomErrorConfig to API format."""
        return self._chaos._serialize_random_error_config(config)

    def _serialize_greylist_config(self, config: GreylistConfig) -> dict[str, Any]:
        """Serialize a GreylistConfig to API format."""
        return self._chaos._serialize_greylist_config(config)

    def _serialize_blackhole_config(self, config: BlackholeConfig) -> dict[str, Any]:
        """Serialize a BlackholeConfig to API format."""
        return self._chaos._serialize_blackhole_config(config)

    def _serialize_chaos_config(self, config: ChaosConfig) -> dict[str, Any]:
        """Serialize a ChaosConfig to API format."""
        return self._chaos._serialize_chaos_config(config)

    def _parse_latency_config(self, data: dict[str, Any]) -> LatencyConfig:
        """Parse LatencyConfig from API response."""
        return self._chaos._parse_latency_config(data)

    def _parse_connection_drop_config(self, data: dict[str, Any]) -> ConnectionDropConfig:
        """Parse ConnectionDropConfig from API response."""
        return self._chaos._parse_connection_drop_config(data)

    def _parse_random_error_config(self, data: dict[str, Any]) -> RandomErrorConfig:
        """Parse RandomErrorConfig from API response."""
        return self._chaos._parse_random_error_config(data)

    def _parse_greylist_config(self, data: dict[str, Any]) -> GreylistConfig:
        """Parse GreylistConfig from API response."""
        return self._chaos._parse_greylist_config(data)

    def _parse_blackhole_config(self, data: dict[str, Any]) -> BlackholeConfig:
        """Parse BlackholeConfig from API response."""
        return self._chaos._parse_blackhole_config(data)

    def _parse_chaos_config(self, data: dict[str, Any]) -> ChaosConfig:
        """Parse ChaosConfig from API response."""
        return self._chaos._parse_chaos_config(data)

    async def get_inbox_chaos(self, email_address: str) -> ChaosConfig:
        """Get the chaos configuration for an inbox.

        Args:
            email_address: The email address of the inbox.

        Returns:
            ChaosConfig with current chaos settings.

        Raises:
            ApiError: If chaos is disabled globally (403) or other API errors.
            InboxNotFoundError: If the inbox is not found.
        """
        return await self._chaos.get_inbox_chaos(email_address)

    async def set_inbox_chaos(self, email_address: str, config: ChaosConfig) -> ChaosConfig:
        """Set the chaos configuration for an inbox.

        Args:
            email_address: The email address of the inbox.
            config: The chaos configuration to apply.

        Returns:
            ChaosConfig with the applied settings (including defaults).

        Raises:
            ApiError: If chaos is disabled globally (403) or validation fails (400).
            InboxNotFoundError: If the inbox is not found.
        """
        return await self._chaos.set_inbox_chaos(email_address, config)

    async def disable_inbox_chaos(self, email_address: str) -> None:
        """Disable all chaos for an inbox.

        Args:
            email_address: The email address of the inbox.

        Raises:
            ApiError: If chaos is disabled globally (403) or other API errors.
            InboxNotFoundError: If the inbox is not found.
        """
        await self._chaos.disable_inbox_chaos(email_address)
