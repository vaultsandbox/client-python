"""Tests for VaultSandboxClient and InboxMonitor."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from vaultsandbox import (
    DEFAULT_MAX_RETRIES,
    DEFAULT_POLLING_INTERVAL_MS,
    DEFAULT_POLLING_MAX_BACKOFF_MS,
    DEFAULT_RETRY_DELAY_MS,
    DEFAULT_RETRY_STATUS_CODES,
    DEFAULT_SSE_MAX_RECONNECT_ATTEMPTS,
    DEFAULT_SSE_RECONNECT_INTERVAL_MS,
    DEFAULT_TIMEOUT_MS,
    DeliveryStrategyType,
    ExportedInbox,
    VaultSandboxClient,
)
from vaultsandbox.client import InboxMonitor
from vaultsandbox.errors import (
    InboxAlreadyExistsError,
    InboxNotFoundError,
    InvalidImportDataError,
)


class TestVaultSandboxClientInit:
    """Tests for VaultSandboxClient initialization."""

    def test_default_configuration(self) -> None:
        """Test client initializes with default configuration values."""
        client = VaultSandboxClient(api_key="test-key")
        assert client._config.api_key == "test-key"
        assert client._config.base_url == "https://smtp.vaultsandbox.com"
        assert client._config.timeout == DEFAULT_TIMEOUT_MS
        assert client._config.max_retries == DEFAULT_MAX_RETRIES
        assert client._config.retry_delay == DEFAULT_RETRY_DELAY_MS
        assert client._config.retry_on_status_codes == DEFAULT_RETRY_STATUS_CODES
        assert client._config.strategy == DeliveryStrategyType.AUTO

    def test_custom_configuration(self) -> None:
        """Test client initializes with custom configuration values."""
        client = VaultSandboxClient(
            api_key="test-key",
            base_url="https://custom.url",
            timeout=60000,
            max_retries=5,
            retry_delay=2000,
            retry_on_status_codes=(500, 503),
            strategy=DeliveryStrategyType.POLLING,
            polling_interval=5000,
            polling_max_backoff=60000,
            sse_reconnect_interval=10000,
            sse_max_reconnect_attempts=5,
        )
        assert client._config.api_key == "test-key"
        assert client._config.base_url == "https://custom.url"
        assert client._config.timeout == 60000
        assert client._config.max_retries == 5
        assert client._config.retry_delay == 2000
        assert client._config.retry_on_status_codes == (500, 503)
        assert client._config.strategy == DeliveryStrategyType.POLLING
        assert client._polling_config.initial_interval == 5000
        assert client._polling_config.max_backoff == 60000
        assert client._sse_config.reconnect_interval == 10000
        assert client._sse_config.max_reconnect_attempts == 5

    def test_default_constants_match_expected_values(self) -> None:
        """Test that default constants have expected values."""
        assert DEFAULT_TIMEOUT_MS == 30_000
        assert DEFAULT_RETRY_DELAY_MS == 1_000
        assert DEFAULT_MAX_RETRIES == 3
        assert DEFAULT_POLLING_INTERVAL_MS == 2_000
        assert DEFAULT_POLLING_MAX_BACKOFF_MS == 30_000
        assert DEFAULT_SSE_RECONNECT_INTERVAL_MS == 5_000
        assert DEFAULT_SSE_MAX_RECONNECT_ATTEMPTS == 10
        assert DEFAULT_RETRY_STATUS_CODES == (408, 429, 500, 502, 503, 504)

    def test_custom_retry_settings(self) -> None:
        """Provide custom retry settings independently."""
        client = VaultSandboxClient(
            api_key="test-key",
            max_retries=5,
            retry_delay=2000,
        )
        assert client._config.max_retries == 5
        assert client._config.retry_delay == 2000
        # Other settings should remain default
        assert client._config.timeout == DEFAULT_TIMEOUT_MS
        assert client._config.strategy == DeliveryStrategyType.AUTO

    def test_custom_strategy_explicit(self) -> None:
        """Specify polling/SSE/auto strategy explicitly."""
        client_polling = VaultSandboxClient(
            api_key="test-key",
            strategy=DeliveryStrategyType.POLLING,
        )
        assert client_polling._config.strategy == DeliveryStrategyType.POLLING

        client_sse = VaultSandboxClient(
            api_key="test-key",
            strategy=DeliveryStrategyType.SSE,
        )
        assert client_sse._config.strategy == DeliveryStrategyType.SSE

        client_auto = VaultSandboxClient(
            api_key="test-key",
            strategy=DeliveryStrategyType.AUTO,
        )
        assert client_auto._config.strategy == DeliveryStrategyType.AUTO

    def test_polling_config_custom(self) -> None:
        """Custom polling interval and backoff configuration."""
        client = VaultSandboxClient(
            api_key="test-key",
            polling_interval=500,
            polling_max_backoff=10000,
        )
        assert client._polling_config.initial_interval == 500
        assert client._polling_config.max_backoff == 10000

    def test_sse_config_custom(self) -> None:
        """Custom SSE reconnect interval and max attempts."""
        client = VaultSandboxClient(
            api_key="test-key",
            sse_reconnect_interval=2000,
            sse_max_reconnect_attempts=15,
        )
        assert client._sse_config.reconnect_interval == 2000
        assert client._sse_config.max_reconnect_attempts == 15


class TestVaultSandboxClientExportImport:
    """Tests for inbox export/import functionality."""

    def test_export_inbox_not_found(self) -> None:
        """Test export_inbox raises InboxNotFoundError for unknown inbox."""
        client = VaultSandboxClient(api_key="test-key")
        with pytest.raises(InboxNotFoundError, match="Inbox not found"):
            client.export_inbox("unknown@example.com")

    @pytest.mark.asyncio
    async def test_import_inbox_missing_fields(self) -> None:
        """Test import_inbox raises InvalidImportDataError for missing fields."""
        client = VaultSandboxClient(api_key="test-key")

        # Mock _ensure_initialized to avoid network calls
        mock_strategy = MagicMock()
        mock_server_info = MagicMock()
        mock_server_info.server_sig_pk = "test-server-pk"
        client._strategy = mock_strategy
        client._server_info = mock_server_info
        client._initialized = True

        # Missing email_address
        with pytest.raises(InvalidImportDataError, match="Missing email_address"):
            await client.import_inbox(
                ExportedInbox(
                    email_address="",
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="hash",
                    server_sig_pk="pk",
                    public_key_b64="pk",
                    secret_key_b64="sk",
                    exported_at="2025-01-01T00:00:00Z",
                )
            )

    @pytest.mark.asyncio
    async def test_import_inbox_already_exists(self) -> None:
        """Test import_inbox raises InboxAlreadyExistsError for duplicate inbox."""
        client = VaultSandboxClient(api_key="test-key")

        # Mock _ensure_initialized to set up strategy and server_info
        mock_strategy = MagicMock()
        mock_server_info = MagicMock()
        mock_server_info.server_sig_pk = "test-server-pk"
        client._strategy = mock_strategy
        client._server_info = mock_server_info
        client._initialized = True

        # Add a fake inbox to the client
        client._inboxes["test@example.com"] = MagicMock()

        # Create valid import data with proper key lengths
        from vaultsandbox.crypto import generate_keypair, to_base64

        keypair = generate_keypair()

        with pytest.raises(InboxAlreadyExistsError, match="already exists"):
            await client.import_inbox(
                ExportedInbox(
                    email_address="test@example.com",
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="hash",
                    server_sig_pk="test-server-pk",
                    public_key_b64=to_base64(keypair.public_key),
                    secret_key_b64=to_base64(keypair.secret_key),
                    exported_at="2025-01-01T00:00:00Z",
                )
            )


class TestVaultSandboxClientMonitor:
    """Tests for monitor_inboxes functionality."""

    def test_monitor_inboxes_not_initialized(self) -> None:
        """Test monitor_inboxes raises RuntimeError when not initialized."""
        client = VaultSandboxClient(api_key="test-key")
        with pytest.raises(RuntimeError, match="Client not initialized"):
            client.monitor_inboxes([])

    def test_monitor_inboxes_returns_monitor(self) -> None:
        """Test monitor_inboxes returns InboxMonitor instance."""
        client = VaultSandboxClient(api_key="test-key")
        mock_strategy = MagicMock()
        client._strategy = mock_strategy

        inboxes = [MagicMock(), MagicMock()]
        monitor = client.monitor_inboxes(inboxes)

        assert isinstance(monitor, InboxMonitor)
        assert monitor._inboxes == inboxes
        assert monitor._strategy == mock_strategy


class TestInboxMonitor:
    """Tests for InboxMonitor class."""

    def test_on_email_registers_callback(self) -> None:
        """Test on_email registers callback and returns self."""
        mock_strategy = MagicMock()
        monitor = InboxMonitor(inboxes=[], strategy=mock_strategy)

        callback = MagicMock()
        result = monitor.on_email(callback)

        assert result is monitor
        assert callback in monitor._callbacks

    def test_on_email_chains_multiple_callbacks(self) -> None:
        """Test multiple callbacks can be chained."""
        mock_strategy = MagicMock()
        monitor = InboxMonitor(inboxes=[], strategy=mock_strategy)

        callback1 = MagicMock()
        callback2 = MagicMock()

        monitor.on_email(callback1).on_email(callback2)

        assert callback1 in monitor._callbacks
        assert callback2 in monitor._callbacks

    @pytest.mark.asyncio
    async def test_start_returns_self(self) -> None:
        """Test start returns self for chaining."""
        mock_strategy = MagicMock()
        monitor = InboxMonitor(inboxes=[], strategy=mock_strategy)

        result = await monitor.start()
        assert result is monitor
        assert monitor._started is True

    @pytest.mark.asyncio
    async def test_start_does_not_restart(self) -> None:
        """Test start does not restart if already started."""
        mock_strategy = MagicMock()
        mock_inbox = MagicMock()
        mock_inbox.on_new_email = AsyncMock(return_value=MagicMock())
        monitor = InboxMonitor(inboxes=[mock_inbox], strategy=mock_strategy)

        await monitor.start()
        await monitor.start()  # Second call should be no-op

        # on_new_email should only be called once
        assert mock_inbox.on_new_email.call_count == 1

    @pytest.mark.asyncio
    async def test_unsubscribe_clears_subscriptions(self) -> None:
        """Test unsubscribe clears all subscriptions."""
        mock_strategy = MagicMock()
        mock_strategy.unsubscribe = AsyncMock()
        monitor = InboxMonitor(inboxes=[], strategy=mock_strategy)
        monitor._subscriptions = [MagicMock(), MagicMock()]
        monitor._started = True

        await monitor.unsubscribe()

        assert len(monitor._subscriptions) == 0
        assert monitor._started is False
        assert mock_strategy.unsubscribe.call_count == 2


class TestVaultSandboxClientRuntimeChecks:
    """Tests for runtime checks that replaced assert statements."""

    @pytest.mark.asyncio
    async def test_get_server_info_uninitialized(self) -> None:
        """Test get_server_info raises RuntimeError when not initialized."""
        client = VaultSandboxClient(api_key="test-key")
        # Mock _ensure_initialized to not actually initialize
        client._ensure_initialized = AsyncMock()
        client._server_info = None

        with pytest.raises(RuntimeError, match="Client not initialized"):
            await client.get_server_info()

    @pytest.mark.asyncio
    async def test_create_inbox_uninitialized_strategy(self) -> None:
        """Test create_inbox raises RuntimeError when strategy is None."""
        client = VaultSandboxClient(api_key="test-key")
        client._ensure_initialized = AsyncMock()
        client._strategy = None

        with pytest.raises(RuntimeError, match="Client not initialized"):
            await client.create_inbox()

    @pytest.mark.asyncio
    async def test_import_inbox_uninitialized_strategy(self) -> None:
        """Test import_inbox raises RuntimeError when strategy is None."""
        client = VaultSandboxClient(api_key="test-key")
        client._ensure_initialized = AsyncMock()
        client._strategy = None

        with pytest.raises(RuntimeError, match="Client not initialized"):
            await client.import_inbox(
                ExportedInbox(
                    email_address="test@example.com",
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="hash",
                    server_sig_pk="pk",
                    public_key_b64="pk",
                    secret_key_b64="sk",
                    exported_at="2025-01-01T00:00:00Z",
                )
            )

    @pytest.mark.asyncio
    async def test_import_inbox_uninitialized_server_info(self) -> None:
        """Test import_inbox raises RuntimeError when server_info is None."""
        client = VaultSandboxClient(api_key="test-key")
        client._ensure_initialized = AsyncMock()
        client._strategy = MagicMock()
        client._server_info = None

        with pytest.raises(RuntimeError, match="Client not initialized"):
            await client.import_inbox(
                ExportedInbox(
                    email_address="test@example.com",
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="hash",
                    server_sig_pk="pk",
                    public_key_b64="pk",
                    secret_key_b64="sk",
                    exported_at="2025-01-01T00:00:00Z",
                )
            )


class TestImportExportValidation:
    """Tests for import/export data validation."""

    @pytest.mark.asyncio
    async def test_import_invalid_base64(self) -> None:
        """Import with invalid base64 keys throws InvalidImportDataError."""
        client = VaultSandboxClient(api_key="test-key")
        mock_strategy = MagicMock()
        mock_server_info = MagicMock()
        mock_server_info.server_sig_pk = "test-server-pk"
        client._strategy = mock_strategy
        client._server_info = mock_server_info
        client._initialized = True

        with pytest.raises(InvalidImportDataError, match="Invalid public key"):
            await client.import_inbox(
                ExportedInbox(
                    email_address="test@example.com",
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="hash",
                    server_sig_pk="test-server-pk",
                    public_key_b64="not!valid!base64!!!",
                    secret_key_b64="also!invalid!!!",
                    exported_at="2025-01-01T00:00:00Z",
                )
            )

    @pytest.mark.asyncio
    async def test_import_wrong_key_length(self) -> None:
        """Import with incorrect key sizes throws InvalidImportDataError."""
        from vaultsandbox.crypto import to_base64

        client = VaultSandboxClient(api_key="test-key")
        mock_strategy = MagicMock()
        mock_server_info = MagicMock()
        mock_server_info.server_sig_pk = "test-server-pk"
        client._strategy = mock_strategy
        client._server_info = mock_server_info
        client._initialized = True

        # Create valid base64 but with wrong key sizes
        with pytest.raises(InvalidImportDataError, match="Invalid public key length"):
            await client.import_inbox(
                ExportedInbox(
                    email_address="test@example.com",
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="hash",
                    server_sig_pk="test-server-pk",
                    public_key_b64=to_base64(b"short"),
                    secret_key_b64=to_base64(b"short"),
                    exported_at="2025-01-01T00:00:00Z",
                )
            )

    @pytest.mark.asyncio
    async def test_import_server_mismatch(self) -> None:
        """Import with different server_sig_pk throws InvalidImportDataError."""
        from vaultsandbox.crypto import generate_keypair, to_base64

        client = VaultSandboxClient(api_key="test-key")
        mock_strategy = MagicMock()
        mock_server_info = MagicMock()
        mock_server_info.server_sig_pk = "expected-server-pk"
        client._strategy = mock_strategy
        client._server_info = mock_server_info
        client._initialized = True

        keypair = generate_keypair()

        with pytest.raises(
            InvalidImportDataError, match="Server signing public key does not match"
        ):
            await client.import_inbox(
                ExportedInbox(
                    email_address="test@example.com",
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="hash",
                    server_sig_pk="different-server-pk",
                    public_key_b64=to_base64(keypair.public_key),
                    secret_key_b64=to_base64(keypair.secret_key),
                    exported_at="2025-01-01T00:00:00Z",
                )
            )

    @pytest.mark.asyncio
    async def test_import_inbox_missing_inbox_hash(self) -> None:
        """Import with empty inbox_hash throws InvalidImportDataError."""
        from vaultsandbox.crypto import generate_keypair, to_base64

        client = VaultSandboxClient(api_key="test-key")
        mock_strategy = MagicMock()
        mock_server_info = MagicMock()
        mock_server_info.server_sig_pk = "test-server-pk"
        client._strategy = mock_strategy
        client._server_info = mock_server_info
        client._initialized = True

        keypair = generate_keypair()

        with pytest.raises(InvalidImportDataError, match="Missing inbox_hash"):
            await client.import_inbox(
                ExportedInbox(
                    email_address="test@example.com",
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="",  # Empty
                    server_sig_pk="test-server-pk",
                    public_key_b64=to_base64(keypair.public_key),
                    secret_key_b64=to_base64(keypair.secret_key),
                    exported_at="2025-01-01T00:00:00Z",
                )
            )


class TestExportInbox:
    """Tests for export inbox functionality."""

    def test_export_inbox_returns_exported_inbox(self) -> None:
        """Test that export_inbox returns an ExportedInbox object."""
        from vaultsandbox.crypto import generate_keypair, to_base64

        client = VaultSandboxClient(api_key="test-key")

        # Create a mock inbox with proper export() method
        keypair = generate_keypair()
        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.export.return_value = ExportedInbox(
            email_address="test@example.com",
            inbox_hash="test-hash",
            expires_at="2025-01-01T00:00:00Z",
            server_sig_pk="server-pk",
            public_key_b64=to_base64(keypair.public_key),
            secret_key_b64=to_base64(keypair.secret_key),
            exported_at="2025-01-01T00:00:00Z",
        )

        client._inboxes["test@example.com"] = mock_inbox

        exported = client.export_inbox(mock_inbox)

        assert isinstance(exported, ExportedInbox)
        assert exported.email_address == "test@example.com"
        assert exported.inbox_hash == "test-hash"
        assert exported.server_sig_pk == "server-pk"
        assert exported.public_key_b64 is not None
        assert exported.secret_key_b64 is not None
        assert exported.exported_at is not None

    def test_export_inbox_by_email_address(self) -> None:
        """Test export using email address string works."""
        from vaultsandbox.crypto import generate_keypair, to_base64

        client = VaultSandboxClient(api_key="test-key")

        # Create a mock inbox with proper export() method
        keypair = generate_keypair()
        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.export.return_value = ExportedInbox(
            email_address="test@example.com",
            inbox_hash="test-hash",
            expires_at="2025-01-01T00:00:00Z",
            server_sig_pk="server-pk",
            public_key_b64=to_base64(keypair.public_key),
            secret_key_b64=to_base64(keypair.secret_key),
            exported_at="2025-01-01T00:00:00Z",
        )

        client._inboxes["test@example.com"] = mock_inbox

        # Export by email address string
        exported = client.export_inbox("test@example.com")

        assert exported.email_address == "test@example.com"

    def test_export_inbox_has_valid_timestamps(self) -> None:
        """Check timestamp fields are valid ISO 8601 format."""
        from vaultsandbox.crypto import generate_keypair, to_base64

        client = VaultSandboxClient(api_key="test-key")

        keypair = generate_keypair()
        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.export.return_value = ExportedInbox(
            email_address="test@example.com",
            inbox_hash="test-hash",
            expires_at="2025-01-01T00:00:00Z",
            server_sig_pk="server-pk",
            public_key_b64=to_base64(keypair.public_key),
            secret_key_b64=to_base64(keypair.secret_key),
            exported_at="2025-01-01T12:00:00Z",
        )

        client._inboxes["test@example.com"] = mock_inbox

        exported = client.export_inbox(mock_inbox)

        # Should parse without error
        datetime.fromisoformat(exported.expires_at.replace("Z", "+00:00"))
        datetime.fromisoformat(exported.exported_at.replace("Z", "+00:00"))
