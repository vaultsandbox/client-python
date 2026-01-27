"""Inbox API client for VaultSandbox SDK."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from ..types import ChaosConfig, InboxData, InboxEncryptionMode, SyncStatus
from .base_client import BaseApiClient, encode_path_segment

if TYPE_CHECKING:
    from .chaos_client import ChaosApiClient


class InboxApiClient(BaseApiClient):
    """API client for inbox operations.

    Provides methods for creating, deleting, and managing inboxes.
    """

    # Reference to chaos client for serializing chaos config
    _chaos_client: ChaosApiClient | None = None

    def _serialize_chaos_config(self, config: ChaosConfig) -> dict[str, Any]:
        """Serialize a ChaosConfig to API format.

        Delegates to ChaosApiClient if available, otherwise uses simple serialization.
        """
        if self._chaos_client is not None:
            return self._chaos_client._serialize_chaos_config(config)

        # Fallback simple serialization
        result: dict[str, Any] = {"enabled": config.enabled}
        if config.expires_at is not None:
            result["expiresAt"] = config.expires_at
        return result

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
        if spam_analysis is not None:
            body["spamAnalysis"] = spam_analysis
        if chaos is not None:
            body["chaos"] = self._serialize_chaos_config(chaos)

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
        encoded = encode_path_segment(email_address)
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
        encoded = encode_path_segment(email_address)
        response = await self._request("GET", f"/api/inboxes/{encoded}/sync")
        data = response.json()
        return SyncStatus(
            email_count=data["emailCount"],
            emails_hash=data["emailsHash"],
        )
