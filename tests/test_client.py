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
        assert client._config.strategy == DeliveryStrategyType.SSE

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
        assert client._config.strategy == DeliveryStrategyType.SSE

    def test_custom_strategy_explicit(self) -> None:
        """Specify polling/SSE strategy explicitly."""
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

    def test_create_strategy_returns_polling_strategy(self) -> None:
        """Test _create_strategy returns PollingStrategy when strategy is POLLING (line 254)."""
        from vaultsandbox.strategies import PollingStrategy

        client = VaultSandboxClient(
            api_key="test-key",
            strategy=DeliveryStrategyType.POLLING,
        )

        strategy = client._create_strategy()

        assert isinstance(strategy, PollingStrategy)


class TestVaultSandboxClientContextManager:
    """Tests for async context manager methods."""

    @pytest.mark.asyncio
    async def test_aenter_returns_self(self) -> None:
        """Test __aenter__ returns the client instance (line 220)."""
        client = VaultSandboxClient(api_key="test-key")
        result = await client.__aenter__()
        assert result is client

    @pytest.mark.asyncio
    async def test_aexit_calls_close(self) -> None:
        """Test __aexit__ calls close (line 224)."""
        client = VaultSandboxClient(api_key="test-key")
        client.close = AsyncMock()
        await client.__aexit__(None, None, None)
        client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_context_manager_usage(self) -> None:
        """Test using client as async context manager."""
        async with VaultSandboxClient(api_key="test-key") as client:
            assert isinstance(client, VaultSandboxClient)


class TestVaultSandboxClientInitialization:
    """Tests for client initialization methods."""

    @pytest.mark.asyncio
    async def test_ensure_initialized_fetches_server_info(self) -> None:
        """Test _ensure_initialized fetches server info and creates strategy (lines 232-237)."""
        client = VaultSandboxClient(api_key="test-key")

        mock_server_info = MagicMock()
        mock_server_info.server_sig_pk = "test-pk"
        client._api_client.get_server_info = AsyncMock(return_value=mock_server_info)

        await client._ensure_initialized()

        assert client._initialized is True
        assert client._server_info == mock_server_info
        assert client._strategy is not None
        client._api_client.get_server_info.assert_called_once()

    @pytest.mark.asyncio
    async def test_ensure_initialized_skips_if_already_initialized(self) -> None:
        """Test _ensure_initialized is a no-op if already initialized."""
        client = VaultSandboxClient(api_key="test-key")
        client._initialized = True
        client._api_client.get_server_info = AsyncMock()

        await client._ensure_initialized()

        client._api_client.get_server_info.assert_not_called()


class TestVaultSandboxClientClose:
    """Tests for client close method."""

    @pytest.mark.asyncio
    async def test_close_clears_inboxes_and_strategy(self) -> None:
        """Test close clears resources (lines 264-274)."""
        client = VaultSandboxClient(api_key="test-key")

        # Set up mock strategy
        mock_strategy = MagicMock()
        mock_strategy.close = AsyncMock()
        client._strategy = mock_strategy
        client._inboxes = {"test@example.com": MagicMock()}
        client._initialized = True

        await client.close()

        assert len(client._inboxes) == 0
        assert client._strategy is None
        assert client._initialized is False
        mock_strategy.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_handles_none_strategy(self) -> None:
        """Test close handles None strategy gracefully."""
        client = VaultSandboxClient(api_key="test-key")
        client._strategy = None

        # Should not raise
        await client.close()


class TestVaultSandboxClientCheckKey:
    """Tests for check_key method."""

    @pytest.mark.asyncio
    async def test_check_key_returns_api_result(self) -> None:
        """Test check_key delegates to API client (line 282)."""
        client = VaultSandboxClient(api_key="test-key")
        client._api_client.check_key = AsyncMock(return_value=True)

        result = await client.check_key()

        assert result is True
        client._api_client.check_key.assert_called_once()


class TestVaultSandboxClientGetServerInfo:
    """Tests for get_server_info method."""

    @pytest.mark.asyncio
    async def test_get_server_info_returns_info(self) -> None:
        """Test get_server_info returns server info (line 293)."""
        client = VaultSandboxClient(api_key="test-key")

        mock_server_info = MagicMock()
        client._server_info = mock_server_info
        client._initialized = True
        client._ensure_initialized = AsyncMock()

        result = await client.get_server_info()

        assert result is mock_server_info


class TestVaultSandboxClientCreateInbox:
    """Tests for create_inbox method."""

    @pytest.mark.asyncio
    async def test_create_inbox_success(self) -> None:
        """Test create_inbox creates and returns inbox (lines 311-337)."""

        client = VaultSandboxClient(api_key="test-key")

        # Mock the dependencies
        mock_strategy = MagicMock()
        client._strategy = mock_strategy
        client._initialized = True
        client._ensure_initialized = AsyncMock()

        mock_inbox_data = MagicMock()
        mock_inbox_data.email_address = "test@example.com"
        mock_inbox_data.expires_at = "2025-01-01T00:00:00Z"
        mock_inbox_data.inbox_hash = "test-hash"
        mock_inbox_data.encrypted = True
        mock_inbox_data.server_sig_pk = "test-server-pk"
        client._api_client.create_inbox = AsyncMock(return_value=mock_inbox_data)

        inbox = await client.create_inbox()

        assert inbox.email_address == "test@example.com"
        assert inbox in client._inboxes.values()

    @pytest.mark.asyncio
    async def test_create_inbox_with_options(self) -> None:
        """Test create_inbox passes options to API."""
        from vaultsandbox.types import CreateInboxOptions

        client = VaultSandboxClient(api_key="test-key")

        mock_strategy = MagicMock()
        client._strategy = mock_strategy
        client._initialized = True
        client._ensure_initialized = AsyncMock()

        mock_inbox_data = MagicMock()
        mock_inbox_data.email_address = "custom@example.com"
        mock_inbox_data.expires_at = "2025-01-01T00:00:00Z"
        mock_inbox_data.inbox_hash = "test-hash"
        mock_inbox_data.encrypted = True
        mock_inbox_data.server_sig_pk = "test-server-pk"
        client._api_client.create_inbox = AsyncMock(return_value=mock_inbox_data)

        options = CreateInboxOptions(ttl=3600, email_address="custom@example.com")
        await client.create_inbox(options)

        client._api_client.create_inbox.assert_called_once()
        call_kwargs = client._api_client.create_inbox.call_args.kwargs
        assert call_kwargs["ttl"] == 3600
        assert call_kwargs["email_address"] == "custom@example.com"

    @pytest.mark.asyncio
    async def test_create_plain_inbox(self) -> None:
        """Test create_inbox with encryption='plain' creates unencrypted inbox."""
        from vaultsandbox.types import CreateInboxOptions

        client = VaultSandboxClient(api_key="test-key")

        mock_strategy = MagicMock()
        client._strategy = mock_strategy
        client._initialized = True
        client._ensure_initialized = AsyncMock()

        # Mock server info with encryption policy that allows plain
        mock_server_info = MagicMock()
        mock_server_info.encryption_policy = "enabled"
        client._server_info = mock_server_info

        mock_inbox_data = MagicMock()
        mock_inbox_data.email_address = "plain@example.com"
        mock_inbox_data.expires_at = "2025-01-01T00:00:00Z"
        mock_inbox_data.inbox_hash = "test-hash"
        mock_inbox_data.encrypted = False
        mock_inbox_data.server_sig_pk = None
        client._api_client.create_inbox = AsyncMock(return_value=mock_inbox_data)

        options = CreateInboxOptions(encryption="plain")
        inbox = await client.create_inbox(options)

        # Should not generate keypair for plain inbox
        client._api_client.create_inbox.assert_called_once()
        call_args = client._api_client.create_inbox.call_args
        assert call_args[0][0] is None  # client_kem_pk should be None
        assert call_args.kwargs["encryption"] == "plain"
        assert inbox.encrypted is False

    @pytest.mark.asyncio
    async def test_create_encrypted_inbox_explicit(self) -> None:
        """Test create_inbox with encryption='encrypted' creates encrypted inbox."""
        from vaultsandbox.types import CreateInboxOptions

        client = VaultSandboxClient(api_key="test-key")

        mock_strategy = MagicMock()
        client._strategy = mock_strategy
        client._initialized = True
        client._ensure_initialized = AsyncMock()

        # Mock server info with encryption policy that allows override
        mock_server_info = MagicMock()
        mock_server_info.encryption_policy = "disabled"
        client._server_info = mock_server_info

        mock_inbox_data = MagicMock()
        mock_inbox_data.email_address = "encrypted@example.com"
        mock_inbox_data.expires_at = "2025-01-01T00:00:00Z"
        mock_inbox_data.inbox_hash = "test-hash"
        mock_inbox_data.encrypted = True
        mock_inbox_data.server_sig_pk = "test-server-pk"
        client._api_client.create_inbox = AsyncMock(return_value=mock_inbox_data)

        options = CreateInboxOptions(encryption="encrypted")
        inbox = await client.create_inbox(options)

        # Should generate keypair for encrypted inbox
        client._api_client.create_inbox.assert_called_once()
        call_args = client._api_client.create_inbox.call_args
        assert call_args[0][0] is not None  # client_kem_pk should be set
        assert call_args.kwargs["encryption"] == "encrypted"
        assert inbox.encrypted is True


class TestVaultSandboxClientDeleteAllInboxes:
    """Tests for delete_all_inboxes method."""

    @pytest.mark.asyncio
    async def test_delete_all_inboxes_clears_cache_and_calls_api(self) -> None:
        """Test delete_all_inboxes clears cache and calls API (lines 346-348)."""
        client = VaultSandboxClient(api_key="test-key")
        client._inboxes = {"test@example.com": MagicMock()}
        client._api_client.delete_all_inboxes = AsyncMock(return_value=5)

        result = await client.delete_all_inboxes()

        assert result == 5
        assert len(client._inboxes) == 0
        client._api_client.delete_all_inboxes.assert_called_once()


class TestVaultSandboxClientExportToFile:
    """Tests for export_inbox_to_file method."""

    @pytest.mark.asyncio
    async def test_export_inbox_to_file(self, tmp_path) -> None:
        """Test export_inbox_to_file writes JSON file (lines 414-427)."""
        import json

        from vaultsandbox.crypto import generate_keypair, to_base64url

        client = VaultSandboxClient(api_key="test-key")

        keypair = generate_keypair()
        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.export.return_value = ExportedInbox(
            version=1,
            email_address="test@example.com",
            inbox_hash="test-hash",
            expires_at="2025-01-01T00:00:00Z",
            encrypted=True,
            email_auth=False,
            exported_at="2025-01-01T12:00:00Z",
            server_sig_pk="server-pk",
            secret_key=to_base64url(keypair.secret_key),
        )

        client._inboxes["test@example.com"] = mock_inbox

        file_path = tmp_path / "exported_inbox.json"
        await client.export_inbox_to_file(mock_inbox, file_path)

        # Verify file was written with correct camelCase keys
        data = json.loads(file_path.read_text())
        assert data["version"] == 1
        assert data["emailAddress"] == "test@example.com"
        assert data["inboxHash"] == "test-hash"
        assert data["serverSigPk"] == "server-pk"
        assert "secretKey" in data
        assert data["exportedAt"] == "2025-01-01T12:00:00Z"


class TestImportInboxSuccess:
    """Tests for successful import_inbox scenarios."""

    @pytest.mark.asyncio
    async def test_import_inbox_success(self) -> None:
        """Test import_inbox creates inbox from exported data (lines 473-487, 523)."""
        from vaultsandbox.crypto import generate_keypair, to_base64url

        client = VaultSandboxClient(api_key="test-key")
        mock_strategy = MagicMock()
        mock_server_info = MagicMock()

        keypair = generate_keypair()
        server_sig_pk = to_base64url(b"\x00" * 1952)
        mock_server_info.server_sig_pk = server_sig_pk

        client._strategy = mock_strategy
        client._server_info = mock_server_info
        client._initialized = True

        exported_data = ExportedInbox(
            version=1,
            email_address="test@example.com",
            expires_at="2025-01-01T00:00:00Z",
            inbox_hash="test-hash",
            encrypted=True,
            email_auth=False,
            exported_at="2025-01-01T00:00:00Z",
            server_sig_pk=server_sig_pk,
            secret_key=to_base64url(keypair.secret_key),
        )

        inbox = await client.import_inbox(exported_data)

        assert inbox.email_address == "test@example.com"
        assert inbox.inbox_hash == "test-hash"
        assert "test@example.com" in client._inboxes

    @pytest.mark.asyncio
    async def test_import_inbox_from_file_success(self, tmp_path) -> None:
        """Test import_inbox_from_file returns inbox (line 523)."""
        import json

        from vaultsandbox.crypto import generate_keypair, to_base64url

        client = VaultSandboxClient(api_key="test-key")
        mock_strategy = MagicMock()
        mock_server_info = MagicMock()

        keypair = generate_keypair()
        server_sig_pk = to_base64url(b"\x00" * 1952)
        mock_server_info.server_sig_pk = server_sig_pk

        client._strategy = mock_strategy
        client._server_info = mock_server_info
        client._initialized = True

        # Create valid JSON file
        file_path = tmp_path / "inbox.json"
        file_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "emailAddress": "test@example.com",
                    "expiresAt": "2025-01-01T00:00:00Z",
                    "inboxHash": "test-hash",
                    "encrypted": True,
                    "emailAuth": False,
                    "serverSigPk": server_sig_pk,
                    "secretKey": to_base64url(keypair.secret_key),
                    "exportedAt": "2025-01-01T00:00:00Z",
                }
            )
        )

        inbox = await client.import_inbox_from_file(file_path)

        assert inbox.email_address == "test@example.com"


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
        with pytest.raises(InvalidImportDataError, match="Missing emailAddress"):
            await client.import_inbox(
                ExportedInbox(
                    version=1,
                    email_address="",
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="hash",
                    encrypted=True,
                    email_auth=False,
                    exported_at="2025-01-01T00:00:00Z",
                    server_sig_pk="pk",
                    secret_key="sk",
                )
            )

    @pytest.mark.asyncio
    async def test_import_inbox_already_exists(self) -> None:
        """Test import_inbox raises InboxAlreadyExistsError for duplicate inbox."""
        client = VaultSandboxClient(api_key="test-key")

        # Mock _ensure_initialized to set up strategy and server_info
        mock_strategy = MagicMock()
        mock_server_info = MagicMock()
        client._strategy = mock_strategy
        client._server_info = mock_server_info
        client._initialized = True

        # Add a fake inbox to the client
        client._inboxes["test@example.com"] = MagicMock()

        # Create valid import data with proper key lengths
        from vaultsandbox.crypto import generate_keypair, to_base64url

        keypair = generate_keypair()

        # Create a valid server signature public key (1952 bytes)
        server_sig_pk = to_base64url(b"\x00" * 1952)
        mock_server_info.server_sig_pk = server_sig_pk

        with pytest.raises(InboxAlreadyExistsError, match="already exists"):
            await client.import_inbox(
                ExportedInbox(
                    version=1,
                    email_address="test@example.com",
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="hash",
                    encrypted=True,
                    email_auth=False,
                    exported_at="2025-01-01T00:00:00Z",
                    server_sig_pk=server_sig_pk,
                    secret_key=to_base64url(keypair.secret_key),
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

    @pytest.mark.asyncio
    async def test_start_calls_async_callbacks(self) -> None:
        """Test that async callbacks are awaited properly (lines 126-127)."""
        mock_strategy = MagicMock()
        mock_inbox = MagicMock()

        # Track if async callback was called
        callback_called = False

        async def async_callback(inbox, email):
            nonlocal callback_called
            callback_called = True

        # Mock on_new_email to capture the handler
        captured_handler = None

        async def capture_handler(handler):
            nonlocal captured_handler
            captured_handler = handler
            return MagicMock()

        mock_inbox.on_new_email = capture_handler

        monitor = InboxMonitor(inboxes=[mock_inbox], strategy=mock_strategy)
        monitor.on_email(async_callback)

        await monitor.start()

        # Trigger the captured handler with a mock email
        mock_email = MagicMock()
        await captured_handler(mock_email)

        assert callback_called

    @pytest.mark.asyncio
    async def test_start_handles_callback_exception(self) -> None:
        """Test that exceptions in callbacks are logged but don't stop processing (lines 128-129)."""
        mock_strategy = MagicMock()
        mock_inbox = MagicMock()

        # Callback that raises an exception
        def bad_callback(inbox, email):
            raise ValueError("Test error")

        # Mock on_new_email to capture the handler
        captured_handler = None

        async def capture_handler(handler):
            nonlocal captured_handler
            captured_handler = handler
            return MagicMock()

        mock_inbox.on_new_email = capture_handler

        monitor = InboxMonitor(inboxes=[mock_inbox], strategy=mock_strategy)
        monitor.on_email(bad_callback)

        await monitor.start()

        # Trigger the captured handler - should not raise
        mock_email = MagicMock()
        await captured_handler(mock_email)  # Exception is caught and logged

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
                    version=1,
                    email_address="test@example.com",
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="hash",
                    encrypted=True,
                    email_auth=False,
                    exported_at="2025-01-01T00:00:00Z",
                    server_sig_pk="pk",
                    secret_key="sk",
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
                    version=1,
                    email_address="test@example.com",
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="hash",
                    encrypted=True,
                    email_auth=False,
                    exported_at="2025-01-01T00:00:00Z",
                    server_sig_pk="pk",
                    secret_key="sk",
                )
            )


class TestImportExportValidation:
    """Tests for import/export data validation."""

    @pytest.mark.asyncio
    async def test_import_invalid_base64(self) -> None:
        """Import with invalid base64url keys throws InvalidImportDataError."""
        from vaultsandbox.crypto import to_base64url

        client = VaultSandboxClient(api_key="test-key")
        mock_strategy = MagicMock()
        mock_server_info = MagicMock()
        # Create a valid server signature public key (1952 bytes)
        server_sig_pk = to_base64url(b"\x00" * 1952)
        mock_server_info.server_sig_pk = server_sig_pk
        client._strategy = mock_strategy
        client._server_info = mock_server_info
        client._initialized = True

        # Invalid base64url characters (contains !)
        with pytest.raises(InvalidImportDataError, match="Invalid secretKey encoding"):
            await client.import_inbox(
                ExportedInbox(
                    version=1,
                    email_address="test@example.com",
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="hash",
                    encrypted=True,
                    email_auth=False,
                    exported_at="2025-01-01T00:00:00Z",
                    server_sig_pk=server_sig_pk,
                    secret_key="not!valid!base64!!!",
                )
            )

    @pytest.mark.asyncio
    async def test_import_wrong_key_length(self) -> None:
        """Import with incorrect key sizes throws InvalidImportDataError."""
        from vaultsandbox.crypto import to_base64url

        client = VaultSandboxClient(api_key="test-key")
        mock_strategy = MagicMock()
        mock_server_info = MagicMock()
        # Create a valid server signature public key (1952 bytes)
        server_sig_pk = to_base64url(b"\x00" * 1952)
        mock_server_info.server_sig_pk = server_sig_pk
        client._strategy = mock_strategy
        client._server_info = mock_server_info
        client._initialized = True

        # Create valid base64url but with wrong key sizes
        with pytest.raises(InvalidImportDataError, match="Invalid secretKey length"):
            await client.import_inbox(
                ExportedInbox(
                    version=1,
                    email_address="test@example.com",
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="hash",
                    encrypted=True,
                    email_auth=False,
                    exported_at="2025-01-01T00:00:00Z",
                    server_sig_pk=server_sig_pk,
                    secret_key=to_base64url(b"short"),
                )
            )

    @pytest.mark.asyncio
    async def test_import_server_mismatch(self) -> None:
        """Import with different server_sig_pk throws InvalidImportDataError."""
        from vaultsandbox.crypto import generate_keypair, to_base64url

        client = VaultSandboxClient(api_key="test-key")
        mock_strategy = MagicMock()
        mock_server_info = MagicMock()
        # Create a valid server signature public key (1952 bytes)
        expected_server_pk = to_base64url(b"\x00" * 1952)
        mock_server_info.server_sig_pk = expected_server_pk
        client._strategy = mock_strategy
        client._server_info = mock_server_info
        client._initialized = True

        keypair = generate_keypair()
        # Different server key (same length but different content)
        different_server_pk = to_base64url(b"\x01" * 1952)

        with pytest.raises(
            InvalidImportDataError, match="Server signing public key does not match"
        ):
            await client.import_inbox(
                ExportedInbox(
                    version=1,
                    email_address="test@example.com",
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="hash",
                    encrypted=True,
                    email_auth=False,
                    exported_at="2025-01-01T00:00:00Z",
                    server_sig_pk=different_server_pk,
                    secret_key=to_base64url(keypair.secret_key),
                )
            )

    @pytest.mark.asyncio
    async def test_import_inbox_missing_inbox_hash(self) -> None:
        """Import with empty inbox_hash throws InvalidImportDataError."""
        from vaultsandbox.crypto import generate_keypair, to_base64url

        client = VaultSandboxClient(api_key="test-key")
        mock_strategy = MagicMock()
        mock_server_info = MagicMock()
        # Create a valid server signature public key (1952 bytes)
        server_sig_pk = to_base64url(b"\x00" * 1952)
        mock_server_info.server_sig_pk = server_sig_pk
        client._strategy = mock_strategy
        client._server_info = mock_server_info
        client._initialized = True

        keypair = generate_keypair()

        with pytest.raises(InvalidImportDataError, match="Missing inboxHash"):
            await client.import_inbox(
                ExportedInbox(
                    version=1,
                    email_address="test@example.com",
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="",  # Empty
                    encrypted=True,
                    email_auth=False,
                    exported_at="2025-01-01T00:00:00Z",
                    server_sig_pk=server_sig_pk,
                    secret_key=to_base64url(keypair.secret_key),
                )
            )


class TestExportInbox:
    """Tests for export inbox functionality."""

    def test_export_inbox_returns_exported_inbox(self) -> None:
        """Test that export_inbox returns an ExportedInbox object."""
        from vaultsandbox.crypto import generate_keypair, to_base64url

        client = VaultSandboxClient(api_key="test-key")

        # Create a mock inbox with proper export() method
        keypair = generate_keypair()
        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.export.return_value = ExportedInbox(
            version=1,
            email_address="test@example.com",
            inbox_hash="test-hash",
            expires_at="2025-01-01T00:00:00Z",
            encrypted=True,
            email_auth=False,
            exported_at="2025-01-01T00:00:00Z",
            server_sig_pk="server-pk",
            secret_key=to_base64url(keypair.secret_key),
        )

        client._inboxes["test@example.com"] = mock_inbox

        exported = client.export_inbox(mock_inbox)

        assert isinstance(exported, ExportedInbox)
        assert exported.version == 1
        assert exported.email_address == "test@example.com"
        assert exported.inbox_hash == "test-hash"
        assert exported.server_sig_pk == "server-pk"
        assert exported.secret_key is not None
        assert exported.exported_at is not None

    def test_export_inbox_by_email_address(self) -> None:
        """Test export using email address string works."""
        from vaultsandbox.crypto import generate_keypair, to_base64url

        client = VaultSandboxClient(api_key="test-key")

        # Create a mock inbox with proper export() method
        keypair = generate_keypair()
        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.export.return_value = ExportedInbox(
            version=1,
            email_address="test@example.com",
            inbox_hash="test-hash",
            expires_at="2025-01-01T00:00:00Z",
            encrypted=True,
            email_auth=False,
            exported_at="2025-01-01T00:00:00Z",
            server_sig_pk="server-pk",
            secret_key=to_base64url(keypair.secret_key),
        )

        client._inboxes["test@example.com"] = mock_inbox

        # Export by email address string
        exported = client.export_inbox("test@example.com")

        assert exported.email_address == "test@example.com"

    def test_export_inbox_has_valid_timestamps(self) -> None:
        """Check timestamp fields are valid ISO 8601 format."""
        from vaultsandbox.crypto import generate_keypair, to_base64url

        client = VaultSandboxClient(api_key="test-key")

        keypair = generate_keypair()
        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.export.return_value = ExportedInbox(
            version=1,
            email_address="test@example.com",
            inbox_hash="test-hash",
            expires_at="2025-01-01T00:00:00Z",
            encrypted=True,
            email_auth=False,
            exported_at="2025-01-01T12:00:00Z",
            server_sig_pk="server-pk",
            secret_key=to_base64url(keypair.secret_key),
        )

        client._inboxes["test@example.com"] = mock_inbox

        exported = client.export_inbox(mock_inbox)

        # Should parse without error
        datetime.fromisoformat(exported.expires_at.replace("Z", "+00:00"))
        datetime.fromisoformat(exported.exported_at.replace("Z", "+00:00"))


class TestDeleteInbox:
    """Tests for delete_inbox functionality."""

    @pytest.mark.asyncio
    async def test_delete_inbox_removes_from_cache_and_calls_api(self) -> None:
        """Test delete_inbox removes from local cache and calls API (lines 357-359)."""
        client = VaultSandboxClient(api_key="test-key")
        client._api_client.delete_inbox = AsyncMock()

        # Add a mock inbox to the cache
        mock_inbox = MagicMock()
        client._inboxes["test@example.com"] = mock_inbox

        await client.delete_inbox("test@example.com")

        # Verify removed from local cache
        assert "test@example.com" not in client._inboxes
        # Verify API was called
        client._api_client.delete_inbox.assert_called_once_with("test@example.com")

    @pytest.mark.asyncio
    async def test_delete_inbox_not_in_cache_still_calls_api(self) -> None:
        """Test delete_inbox works even if inbox not in local cache."""
        client = VaultSandboxClient(api_key="test-key")
        client._api_client.delete_inbox = AsyncMock()

        # Call delete for an inbox not in local cache
        await client.delete_inbox("notcached@example.com")

        # Verify API was still called
        client._api_client.delete_inbox.assert_called_once_with("notcached@example.com")


class TestImportValidationErrors:
    """Tests for import data validation errors."""

    @pytest.mark.asyncio
    async def test_import_unsupported_version(self) -> None:
        """Test import with unsupported version raises UnsupportedVersionError (line 547)."""
        from vaultsandbox.errors import UnsupportedVersionError

        client = VaultSandboxClient(api_key="test-key")
        client._strategy = MagicMock()
        client._server_info = MagicMock()
        client._initialized = True

        with pytest.raises(UnsupportedVersionError, match="Unsupported export version"):
            await client.import_inbox(
                ExportedInbox(
                    version=999,  # Unsupported version
                    email_address="test@example.com",
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="hash",
                    encrypted=True,
                    email_auth=False,
                    exported_at="2025-01-01T00:00:00Z",
                    server_sig_pk="pk",
                    secret_key="sk",
                )
            )

    @pytest.mark.asyncio
    async def test_import_missing_expires_at(self) -> None:
        """Test import with missing expiresAt raises InvalidImportDataError (line 555)."""
        client = VaultSandboxClient(api_key="test-key")
        client._strategy = MagicMock()
        client._server_info = MagicMock()
        client._initialized = True

        with pytest.raises(InvalidImportDataError, match="Missing expiresAt"):
            await client.import_inbox(
                ExportedInbox(
                    version=1,
                    email_address="test@example.com",
                    expires_at="",  # Empty
                    inbox_hash="hash",
                    encrypted=True,
                    email_auth=False,
                    exported_at="2025-01-01T00:00:00Z",
                    server_sig_pk="pk",
                    secret_key="sk",
                )
            )

    @pytest.mark.asyncio
    async def test_import_missing_server_sig_pk(self) -> None:
        """Test import with missing serverSigPk raises InvalidImportDataError (line 559)."""
        client = VaultSandboxClient(api_key="test-key")
        client._strategy = MagicMock()
        client._server_info = MagicMock()
        client._initialized = True

        with pytest.raises(InvalidImportDataError, match="Missing serverSigPk for encrypted inbox"):
            await client.import_inbox(
                ExportedInbox(
                    version=1,
                    email_address="test@example.com",
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="hash",
                    encrypted=True,
                    email_auth=False,
                    exported_at="2025-01-01T00:00:00Z",
                    server_sig_pk="",  # Empty
                    secret_key="sk",
                )
            )

    @pytest.mark.asyncio
    async def test_import_missing_secret_key(self) -> None:
        """Test import with missing secretKey raises InvalidImportDataError (line 561)."""
        client = VaultSandboxClient(api_key="test-key")
        client._strategy = MagicMock()
        client._server_info = MagicMock()
        client._initialized = True

        with pytest.raises(InvalidImportDataError, match="Missing secretKey for encrypted inbox"):
            await client.import_inbox(
                ExportedInbox(
                    version=1,
                    email_address="test@example.com",
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="hash",
                    encrypted=True,
                    email_auth=False,
                    exported_at="2025-01-01T00:00:00Z",
                    server_sig_pk="pk",
                    secret_key="",  # Empty
                )
            )

    @pytest.mark.asyncio
    async def test_import_invalid_email_no_at_symbol(self) -> None:
        """Test import with email without @ raises InvalidImportDataError (line 566)."""
        client = VaultSandboxClient(api_key="test-key")
        client._strategy = MagicMock()
        client._server_info = MagicMock()
        client._initialized = True

        with pytest.raises(InvalidImportDataError, match="Invalid emailAddress"):
            await client.import_inbox(
                ExportedInbox(
                    version=1,
                    email_address="testexample.com",  # No @ symbol
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="hash",
                    encrypted=True,
                    email_auth=False,
                    exported_at="2025-01-01T00:00:00Z",
                    server_sig_pk="pk",
                    secret_key="sk",
                )
            )

    @pytest.mark.asyncio
    async def test_import_invalid_email_multiple_at_symbols(self) -> None:
        """Test import with email with multiple @ raises InvalidImportDataError."""
        client = VaultSandboxClient(api_key="test-key")
        client._strategy = MagicMock()
        client._server_info = MagicMock()
        client._initialized = True

        with pytest.raises(InvalidImportDataError, match="Invalid emailAddress"):
            await client.import_inbox(
                ExportedInbox(
                    version=1,
                    email_address="test@@example.com",  # Multiple @ symbols
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="hash",
                    encrypted=True,
                    email_auth=False,
                    exported_at="2025-01-01T00:00:00Z",
                    server_sig_pk="pk",
                    secret_key="sk",
                )
            )

    @pytest.mark.asyncio
    async def test_import_invalid_server_sig_pk_length(self) -> None:
        """Test import with wrong serverSigPk length raises InvalidImportDataError (lines 589-592)."""
        from vaultsandbox.crypto import generate_keypair, to_base64url

        client = VaultSandboxClient(api_key="test-key")
        client._strategy = MagicMock()
        client._server_info = MagicMock()
        client._initialized = True

        keypair = generate_keypair()

        with pytest.raises(InvalidImportDataError, match="Invalid serverSigPk length"):
            await client.import_inbox(
                ExportedInbox(
                    version=1,
                    email_address="test@example.com",
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="hash",
                    encrypted=True,
                    email_auth=False,
                    exported_at="2025-01-01T00:00:00Z",
                    server_sig_pk=to_base64url(b"tooshort"),  # Wrong length
                    secret_key=to_base64url(keypair.secret_key),
                )
            )

    @pytest.mark.asyncio
    async def test_import_invalid_server_sig_pk_encoding(self) -> None:
        """Test import with invalid serverSigPk encoding raises InvalidImportDataError (lines 593-596)."""
        from vaultsandbox.crypto import generate_keypair, to_base64url

        client = VaultSandboxClient(api_key="test-key")
        client._strategy = MagicMock()
        client._server_info = MagicMock()
        client._initialized = True

        keypair = generate_keypair()

        with pytest.raises(InvalidImportDataError, match="Invalid serverSigPk encoding"):
            await client.import_inbox(
                ExportedInbox(
                    version=1,
                    email_address="test@example.com",
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="hash",
                    encrypted=True,
                    email_auth=False,
                    exported_at="2025-01-01T00:00:00Z",
                    server_sig_pk="not!valid!base64!!!",  # Invalid encoding
                    secret_key=to_base64url(keypair.secret_key),
                )
            )

    @pytest.mark.asyncio
    async def test_import_invalid_expires_at_format(self) -> None:
        """Test import with invalid expiresAt format raises InvalidImportDataError (lines 601-602)."""
        from vaultsandbox.crypto import generate_keypair, to_base64url

        client = VaultSandboxClient(api_key="test-key")
        client._strategy = MagicMock()
        mock_server_info = MagicMock()
        server_sig_pk = to_base64url(b"\x00" * 1952)
        mock_server_info.server_sig_pk = server_sig_pk
        client._server_info = mock_server_info
        client._initialized = True

        keypair = generate_keypair()

        with pytest.raises(InvalidImportDataError, match="Invalid expiresAt format"):
            await client.import_inbox(
                ExportedInbox(
                    version=1,
                    email_address="test@example.com",
                    expires_at="not-a-valid-timestamp",  # Invalid format
                    inbox_hash="hash",
                    encrypted=True,
                    email_auth=False,
                    exported_at="2025-01-01T00:00:00Z",
                    server_sig_pk=server_sig_pk,
                    secret_key=to_base64url(keypair.secret_key),
                )
            )

    @pytest.mark.asyncio
    async def test_import_invalid_exported_at_format(self) -> None:
        """Test import with invalid exportedAt format raises InvalidImportDataError (lines 607-608)."""
        from vaultsandbox.crypto import generate_keypair, to_base64url

        client = VaultSandboxClient(api_key="test-key")
        client._strategy = MagicMock()
        mock_server_info = MagicMock()
        server_sig_pk = to_base64url(b"\x00" * 1952)
        mock_server_info.server_sig_pk = server_sig_pk
        client._server_info = mock_server_info
        client._initialized = True

        keypair = generate_keypair()

        with pytest.raises(InvalidImportDataError, match="Invalid exportedAt format"):
            await client.import_inbox(
                ExportedInbox(
                    version=1,
                    email_address="test@example.com",
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="hash",
                    encrypted=True,
                    email_auth=False,
                    exported_at="not-a-valid-timestamp",  # Invalid format
                    server_sig_pk=server_sig_pk,
                    secret_key=to_base64url(keypair.secret_key),
                )
            )

    @pytest.mark.asyncio
    async def test_import_invalid_keypair(self) -> None:
        """Test import with invalid keypair raises InvalidImportDataError (line 470)."""
        from unittest.mock import patch

        from vaultsandbox.crypto import to_base64url

        client = VaultSandboxClient(api_key="test-key")
        client._strategy = MagicMock()
        mock_server_info = MagicMock()
        server_sig_pk = to_base64url(b"\x00" * 1952)
        mock_server_info.server_sig_pk = server_sig_pk
        client._server_info = mock_server_info
        client._initialized = True

        # Create a fake secret key with correct size but invalid content
        # ML-KEM secret key size is 2400 bytes
        fake_secret_key = to_base64url(b"\x00" * 2400)

        # Mock validate_keypair to return False
        with (
            patch("vaultsandbox.client.validate_keypair", return_value=False),
            pytest.raises(InvalidImportDataError, match="Invalid keypair"),
        ):
            await client.import_inbox(
                ExportedInbox(
                    version=1,
                    email_address="test@example.com",
                    expires_at="2025-01-01T00:00:00Z",
                    inbox_hash="hash",
                    encrypted=True,
                    email_auth=False,
                    exported_at="2025-01-01T00:00:00Z",
                    server_sig_pk=server_sig_pk,
                    secret_key=fake_secret_key,
                )
            )


class TestImportInboxFromFile:
    """Tests for import_inbox_from_file functionality."""

    @pytest.mark.asyncio
    async def test_import_from_file_invalid_json(self, tmp_path) -> None:
        """Test import from file with invalid JSON raises InvalidImportDataError (lines 506-507)."""
        # Create a file with invalid JSON
        file_path = tmp_path / "invalid.json"
        file_path.write_text("{ invalid json }")

        client = VaultSandboxClient(api_key="test-key")
        client._strategy = MagicMock()
        client._server_info = MagicMock()
        client._initialized = True

        with pytest.raises(InvalidImportDataError, match="Invalid JSON"):
            await client.import_inbox_from_file(file_path)

    @pytest.mark.asyncio
    async def test_import_from_file_missing_required_field(self, tmp_path) -> None:
        """Test import from file with missing field raises InvalidImportDataError (lines 520-521)."""
        import json

        # Create a file with valid JSON but missing required fields
        file_path = tmp_path / "missing_field.json"
        file_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "emailAddress": "test@example.com",
                    # Missing expiresAt, inboxHash, serverSigPk, secretKey
                }
            )
        )

        client = VaultSandboxClient(api_key="test-key")
        client._strategy = MagicMock()
        client._server_info = MagicMock()
        client._initialized = True

        with pytest.raises(InvalidImportDataError, match="Missing required field"):
            await client.import_inbox_from_file(file_path)
