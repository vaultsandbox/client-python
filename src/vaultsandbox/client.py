"""VaultSandboxClient - Main entry point for VaultSandbox SDK."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .constants import (
    DEFAULT_MAX_RETRIES,
    DEFAULT_POLLING_INTERVAL_MS,
    DEFAULT_POLLING_MAX_BACKOFF_MS,
    DEFAULT_RETRY_DELAY_MS,
    DEFAULT_RETRY_STATUS_CODES,
    DEFAULT_SSE_MAX_RECONNECT_ATTEMPTS,
    DEFAULT_SSE_RECONNECT_INTERVAL_MS,
    DEFAULT_TIMEOUT_MS,
)
from .crypto import (
    Keypair,
    derive_public_key_from_secret,
    from_base64url,
    generate_keypair,
    to_base64url,
    validate_keypair,
)
from .crypto.constants import (
    EXPORT_VERSION,
    MLDSA65_PUBLIC_KEY_SIZE,
    MLKEM768_SECRET_KEY_SIZE,
)
from .email import Email
from .errors import (
    InboxAlreadyExistsError,
    InboxNotFoundError,
    InvalidImportDataError,
)
from .http import ApiClient
from .inbox import Inbox
from .strategies import DeliveryStrategy, PollingStrategy, SSEStrategy
from .types import (
    ClientConfig,
    CreateInboxOptions,
    DeliveryStrategyType,
    ExportedInbox,
    PollingConfig,
    ServerInfo,
    SSEConfig,
)
from .utils import parse_iso_timestamp

logger = logging.getLogger("vaultsandbox")


# Type alias for InboxMonitor callbacks that receive both inbox and email
InboxEmailCallback = Callable[[Inbox, Email], Any]


class InboxMonitor:
    """Monitor multiple inboxes for new emails.

    This class provides an event-based interface for monitoring
    multiple inboxes simultaneously.

    Example:
        ```python
        monitor = client.monitor_inboxes([inbox1, inbox2])

        @monitor.on_email
        async def handle_email(inbox: Inbox, email: Email):
            print(f"New email in {inbox.email_address}: {email.subject}")

        await monitor.start()
        ```
    """

    def __init__(
        self,
        inboxes: list[Inbox],
        strategy: DeliveryStrategy,
    ) -> None:
        """Initialize the inbox monitor.

        Args:
            inboxes: List of inboxes to monitor.
            strategy: The delivery strategy to use.
        """
        self._inboxes = inboxes
        self._strategy = strategy
        self._callbacks: list[InboxEmailCallback] = []
        self._subscriptions: list[Any] = []
        self._started = False

    def on_email(self, callback: InboxEmailCallback) -> InboxMonitor:
        """Register a callback for new emails.

        Args:
            callback: Function to call when new emails arrive.
                      Receives (inbox, email) as arguments.

        Returns:
            Self for method chaining.
        """
        self._callbacks.append(callback)
        return self

    async def start(self) -> InboxMonitor:
        """Start monitoring inboxes.

        Returns:
            Self for method chaining.
        """
        if self._started:
            return self

        for inbox in self._inboxes:
            # Create a closure to capture the inbox reference
            def make_handler(inbox_ref: Inbox) -> Callable[[Email], Any]:
                async def handle_email(email: Email) -> None:
                    for callback in self._callbacks:
                        try:
                            result = callback(inbox_ref, email)
                            if asyncio.iscoroutine(result):
                                await result
                        except Exception as e:
                            logger.debug("Error in email callback: %s", e, exc_info=True)

                return handle_email

            handler = make_handler(inbox)
            subscription = await inbox.on_new_email(handler)
            self._subscriptions.append(subscription)

        self._started = True
        return self

    async def unsubscribe(self) -> None:
        """Stop monitoring and unsubscribe from all inboxes."""
        for subscription in self._subscriptions:
            await self._strategy.unsubscribe(subscription)
        self._subscriptions.clear()
        self._started = False


class VaultSandboxClient:
    """Main client for interacting with VaultSandbox API.

    This is the primary entry point for the VaultSandbox SDK.
    It manages inbox creation, delivery strategies, and server communication.

    Example:
        ```python
        async with VaultSandboxClient(api_key="your-api-key") as client:
            inbox = await client.create_inbox()
            email = await inbox.wait_for_email()
            print(f"Received: {email.subject}")
        ```
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = "https://smtp.vaultsandbox.com",
        timeout: int = DEFAULT_TIMEOUT_MS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_delay: int = DEFAULT_RETRY_DELAY_MS,
        retry_on_status_codes: tuple[int, ...] | None = None,
        strategy: DeliveryStrategyType = DeliveryStrategyType.SSE,
        polling_interval: int = DEFAULT_POLLING_INTERVAL_MS,
        polling_max_backoff: int = DEFAULT_POLLING_MAX_BACKOFF_MS,
        sse_reconnect_interval: int = DEFAULT_SSE_RECONNECT_INTERVAL_MS,
        sse_max_reconnect_attempts: int = DEFAULT_SSE_MAX_RECONNECT_ATTEMPTS,
    ) -> None:
        """Initialize the VaultSandbox client.

        Args:
            api_key: API key for authentication.
            base_url: Base URL for the API server.
            timeout: HTTP request timeout in milliseconds.
            max_retries: Maximum number of retry attempts.
            retry_delay: Initial retry delay in milliseconds.
            retry_on_status_codes: HTTP status codes that trigger retries.
                Default: (408, 429, 500, 502, 503, 504)
            strategy: Delivery strategy type (sse or polling).
            polling_interval: Polling interval in milliseconds (default: 2000).
            polling_max_backoff: Maximum backoff delay in milliseconds (default: 30000).
            sse_reconnect_interval: SSE reconnection interval in milliseconds (default: 5000).
            sse_max_reconnect_attempts: Maximum SSE reconnection attempts (default: 10).
        """
        self._config = ClientConfig(
            api_key=api_key,
            base_url=base_url,
            timeout=timeout,
            max_retries=max_retries,
            retry_delay=retry_delay,
            retry_on_status_codes=retry_on_status_codes or DEFAULT_RETRY_STATUS_CODES,
            strategy=strategy,
        )
        # Store strategy configuration
        self._polling_config = PollingConfig(
            initial_interval=polling_interval,
            max_backoff=polling_max_backoff,
        )
        self._sse_config = SSEConfig(
            reconnect_interval=sse_reconnect_interval,
            max_reconnect_attempts=sse_max_reconnect_attempts,
        )
        self._api_client = ApiClient(self._config)
        self._strategy: DeliveryStrategy | None = None
        self._server_info: ServerInfo | None = None
        self._inboxes: dict[str, Inbox] = {}
        self._initialized = False

    async def __aenter__(self) -> VaultSandboxClient:
        """Enter async context manager."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit async context manager."""
        await self.close()

    async def _ensure_initialized(self) -> None:
        """Initialize the client if not already done."""
        if self._initialized:
            return

        # Fetch server info
        self._server_info = await self._api_client.get_server_info()

        # Create delivery strategy
        self._strategy = self._create_strategy()

        self._initialized = True

    def _create_strategy(self) -> DeliveryStrategy:
        """Create the delivery strategy based on configuration.

        Returns:
            A DeliveryStrategy instance.
        """
        strategy_type = self._config.strategy

        if strategy_type == DeliveryStrategyType.SSE:
            return SSEStrategy(self._api_client, self._sse_config)
        else:
            return PollingStrategy(self._api_client, self._polling_config)

    async def close(self) -> None:
        """Close the client and release all resources.

        Note: This does NOT delete inboxes from the server. Inboxes will
        expire based on their TTL. Use delete_all_inboxes() to explicitly
        delete inboxes.
        """
        # Clear local inbox references (do NOT delete from server)
        self._inboxes.clear()

        # Close strategy
        if self._strategy is not None:
            await self._strategy.close()
            self._strategy = None

        # Close API client
        await self._api_client.close()

        self._initialized = False

    async def check_key(self) -> bool:
        """Validate the API key.

        Returns:
            True if the API key is valid.
        """
        return await self._api_client.check_key()

    async def get_server_info(self) -> ServerInfo:
        """Get server information and capabilities.

        Returns:
            ServerInfo with cryptographic configuration.
        """
        await self._ensure_initialized()
        if self._server_info is None:
            raise RuntimeError("Client not initialized. Call create_inbox first.")
        return self._server_info

    def _should_encrypt_inbox(self, encryption_option: str | None) -> bool:
        """Determine if a new inbox should be encrypted based on policy and options.

        Args:
            encryption_option: User's requested encryption mode ('encrypted', 'plain', or None).

        Returns:
            True if the inbox should be encrypted.
        """
        if self._server_info is None:
            return True  # Default to encrypted if server info not available

        policy = self._server_info.encryption_policy

        # If user specified an explicit option, use it (server will validate)
        if encryption_option == "plain":
            return False
        if encryption_option == "encrypted":
            return True

        # Use server default based on policy
        # Default encrypted: policy is 'always' or 'enabled'
        return policy in ("always", "enabled")

    async def create_inbox(
        self,
        options: CreateInboxOptions | None = None,
    ) -> Inbox:
        """Create a new temporary email inbox.

        Args:
            options: Options for inbox creation (TTL, email address, encryption mode).

        Returns:
            A new Inbox instance.
        """
        await self._ensure_initialized()
        if self._strategy is None:
            raise RuntimeError("Client not initialized. Call create_inbox first.")

        options = options or CreateInboxOptions()

        # Determine if encryption should be used
        should_encrypt = self._should_encrypt_inbox(options.encryption)

        # Generate keypair only if encryption is needed
        keypair: Keypair | None = None
        client_kem_pk: str | None = None
        if should_encrypt:
            keypair = generate_keypair()
            client_kem_pk = keypair.public_key_b64

        # Create inbox on server
        inbox_data = await self._api_client.create_inbox(
            client_kem_pk,
            ttl=options.ttl,
            email_address=options.email_address,
            email_auth=options.email_auth,
            encryption=options.encryption,
        )

        # Parse expires_at timestamp
        expires_at = parse_iso_timestamp(inbox_data.expires_at)

        inbox = Inbox(
            email_address=inbox_data.email_address,
            expires_at=expires_at,
            inbox_hash=inbox_data.inbox_hash,
            encrypted=inbox_data.encrypted,
            server_sig_pk=inbox_data.server_sig_pk,
            email_auth=inbox_data.email_auth,
            _keypair=keypair,
            _api_client=self._api_client,
            _strategy=self._strategy,
        )

        self._inboxes[inbox.email_address] = inbox
        return inbox

    async def delete_all_inboxes(self) -> int:
        """Delete all inboxes for the API key.

        Warning:
            This method should never be called during integration tests as it
            deletes ALL inboxes for the API key, which interferes with concurrent
            test runs and other testing activities.

        Returns:
            Number of inboxes deleted.
        """
        # Clear local inbox references
        self._inboxes.clear()

        return await self._api_client.delete_all_inboxes()

    async def delete_inbox(self, email_address: str) -> None:
        """Delete a specific inbox by email address.

        Args:
            email_address: The email address of the inbox to delete.
        """
        # Remove from local cache if present
        self._inboxes.pop(email_address, None)

        await self._api_client.delete_inbox(email_address)

    def monitor_inboxes(self, inboxes: list[Inbox]) -> InboxMonitor:
        """Create a monitor for multiple inboxes.

        Args:
            inboxes: List of inboxes to monitor.

        Returns:
            An InboxMonitor instance.
        """
        if self._strategy is None:
            raise RuntimeError("Client not initialized. Call create_inbox first.")
        return InboxMonitor(inboxes, self._strategy)

    def export_inbox(self, inbox_or_email: Inbox | str) -> ExportedInbox:
        """Export inbox data for persistence/sharing.

        WARNING: Exported data contains private keys. Handle securely.

        Args:
            inbox_or_email: The inbox to export, or its email address string.

        Returns:
            ExportedInbox with keypair and metadata.

        Raises:
            InboxNotFoundError: If the inbox is not found in the client.
        """
        if isinstance(inbox_or_email, str):
            email_address = inbox_or_email
            inbox = self._inboxes.get(email_address)
            if inbox is None:
                raise InboxNotFoundError(f"Inbox not found: {email_address}")
        else:
            inbox = inbox_or_email

        return inbox.export()

    async def export_inbox_to_file(
        self, inbox_or_email: Inbox | str, file_path: str | Path
    ) -> None:
        """Export inbox data to a JSON file.

        Per VaultSandbox spec Section 9.2, the JSON format uses camelCase field names.

        WARNING: Exported data contains private keys. Handle securely.

        Args:
            inbox_or_email: The inbox to export, or its email address string.
            file_path: Path to the output file.

        Raises:
            InboxNotFoundError: If the inbox is not found in the client.
        """
        exported = self.export_inbox(inbox_or_email)
        # Per Section 9.2, use camelCase field names in JSON
        data: dict[str, Any] = {
            "version": exported.version,
            "emailAddress": exported.email_address,
            "expiresAt": exported.expires_at,
            "inboxHash": exported.inbox_hash,
            "encrypted": exported.encrypted,
            "emailAuth": exported.email_auth,
            "exportedAt": exported.exported_at,
        }

        # Only include cryptographic fields for encrypted inboxes
        if exported.encrypted:
            data["serverSigPk"] = exported.server_sig_pk
            data["secretKey"] = exported.secret_key

        path = Path(file_path)
        path.write_text(json.dumps(data, indent=2))

    async def import_inbox(self, data: ExportedInbox) -> Inbox:
        """Import an inbox from exported data.

        Per VaultSandbox spec Section 10, validates and imports inbox data.

        Args:
            data: The exported inbox data.

        Returns:
            The imported Inbox instance.

        Raises:
            InboxAlreadyExistsError: If the inbox already exists.
            InvalidImportDataError: If the import data is invalid.
        """
        await self._ensure_initialized()
        if self._strategy is None:
            raise RuntimeError("Client not initialized. Call create_inbox first.")
        if self._server_info is None:
            raise RuntimeError("Client not initialized. Call create_inbox first.")

        # Validate import data per Section 10.1
        self._validate_import_data(data)

        # Check if inbox already exists (Section 10.4)
        if data.email_address in self._inboxes:
            raise InboxAlreadyExistsError(f"Inbox {data.email_address} already exists")

        keypair: Keypair | None = None

        # Reconstruct keypair only for encrypted inboxes
        if data.encrypted and data.secret_key:
            # Secret key is base64url encoded per spec
            secret_key = from_base64url(data.secret_key)
            # Derive public key from secret key at offset 1152 (Section 4.2)
            public_key = derive_public_key_from_secret(secret_key)
            keypair = Keypair(
                public_key=public_key,
                secret_key=secret_key,
                public_key_b64=to_base64url(public_key),
            )

            # Validate keypair
            if not validate_keypair(keypair):
                raise InvalidImportDataError("Invalid keypair in import data")

        # Parse expires_at timestamp
        expires_at = parse_iso_timestamp(data.expires_at)

        # Create inbox instance per Section 10.3
        inbox = Inbox(
            email_address=data.email_address,
            expires_at=expires_at,
            inbox_hash=data.inbox_hash,
            encrypted=data.encrypted,
            server_sig_pk=data.server_sig_pk,
            email_auth=data.email_auth,
            _keypair=keypair,
            _api_client=self._api_client,
            _strategy=self._strategy,
        )

        self._inboxes[inbox.email_address] = inbox
        return inbox

    async def import_inbox_from_file(self, file_path: str | Path) -> Inbox:
        """Import an inbox from a JSON file.

        Per VaultSandbox spec Section 10, reads and validates the JSON export format.

        Args:
            file_path: Path to the import file.

        Returns:
            The imported Inbox instance.

        Raises:
            InvalidImportDataError: If the JSON is invalid or missing required fields.
        """
        path = Path(file_path)
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            raise InvalidImportDataError(f"Invalid JSON in import file: {e}") from e

        # Per Section 9.2 field names are camelCase
        try:
            exported = ExportedInbox(
                version=data["version"],
                email_address=data["emailAddress"],
                expires_at=data["expiresAt"],
                inbox_hash=data["inboxHash"],
                encrypted=data.get("encrypted", True),  # Default to True for backwards compat
                email_auth=data.get("emailAuth", True),  # Default to True for backwards compat
                exported_at=data.get("exportedAt", ""),
                server_sig_pk=data.get("serverSigPk"),  # Optional for plain inboxes
                secret_key=data.get("secretKey"),  # Optional for plain inboxes
            )
        except KeyError as e:
            raise InvalidImportDataError(f"Missing required field in import file: {e}") from e

        return await self.import_inbox(exported)

    def _validate_import_data(self, data: ExportedInbox) -> None:
        """Validate imported inbox data per Section 10.1.

        Validation steps (must be performed in order):
        1. Validate version == 1
        2. Validate required fields present and non-null
        3. Validate emailAddress contains exactly one @
        4. Validate inboxHash is non-empty
        5. For encrypted inboxes: Validate and decode secretKey (2400 bytes)
        6. For encrypted inboxes: Validate and decode serverSigPk (1952 bytes)
        7. Validate timestamps

        Args:
            data: The exported inbox data.

        Raises:
            InvalidImportDataError: If the data is invalid.
        """
        from .errors import UnsupportedVersionError

        # Step 1: Validate version
        if data.version != EXPORT_VERSION:
            raise UnsupportedVersionError(
                f"Unsupported export version: {data.version}, expected {EXPORT_VERSION}"
            )

        # Step 2: Check required fields (common for both encrypted and plain)
        if not data.email_address:
            raise InvalidImportDataError("Missing emailAddress")
        if not data.expires_at:
            raise InvalidImportDataError("Missing expiresAt")
        if not data.inbox_hash:
            raise InvalidImportDataError("Missing inboxHash")

        # Step 3: Validate emailAddress contains exactly one @
        at_count = data.email_address.count("@")
        if at_count != 1:
            raise InvalidImportDataError(
                f"Invalid emailAddress: must contain exactly one '@', found {at_count}"
            )

        # Step 4: Validate inboxHash is non-empty (already checked above)

        # For encrypted inboxes, validate cryptographic fields
        if data.encrypted:
            if not data.server_sig_pk:
                raise InvalidImportDataError("Missing serverSigPk for encrypted inbox")
            if not data.secret_key:
                raise InvalidImportDataError("Missing secretKey for encrypted inbox")

            # Step 5: Validate and decode secretKey
            try:
                secret_key = from_base64url(data.secret_key)
                if len(secret_key) != MLKEM768_SECRET_KEY_SIZE:
                    raise InvalidImportDataError(
                        f"Invalid secretKey length: {len(secret_key)} bytes, "
                        f"expected {MLKEM768_SECRET_KEY_SIZE}"
                    )
            except InvalidImportDataError:
                raise
            except Exception as e:
                raise InvalidImportDataError(f"Invalid secretKey encoding: {e}") from e

            # Step 6: Validate and decode serverSigPk
            try:
                server_sig_pk = from_base64url(data.server_sig_pk)
                if len(server_sig_pk) != MLDSA65_PUBLIC_KEY_SIZE:
                    raise InvalidImportDataError(
                        f"Invalid serverSigPk length: {len(server_sig_pk)} bytes, "
                        f"expected {MLDSA65_PUBLIC_KEY_SIZE}"
                    )
            except InvalidImportDataError:
                raise
            except Exception as e:
                raise InvalidImportDataError(f"Invalid serverSigPk encoding: {e}") from e

            # Verify server public key matches current server (if connected)
            if self._server_info and data.server_sig_pk != self._server_info.server_sig_pk:
                raise InvalidImportDataError(
                    "Server signing public key does not match current server"
                )

        # Step 7: Validate timestamps
        try:
            parse_iso_timestamp(data.expires_at)
        except ValueError as e:
            raise InvalidImportDataError(f"Invalid expiresAt format: {e}") from e

        if data.exported_at:
            try:
                parse_iso_timestamp(data.exported_at)
            except ValueError as e:
                raise InvalidImportDataError(f"Invalid exportedAt format: {e}") from e
