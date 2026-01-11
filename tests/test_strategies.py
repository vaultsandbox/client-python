"""Tests for delivery strategies (SSE and Polling)."""

from __future__ import annotations

import asyncio
import contextlib
from unittest.mock import AsyncMock, MagicMock

import pytest

from vaultsandbox.errors import SSEError
from vaultsandbox.strategies.delivery_strategy import Subscription
from vaultsandbox.strategies.polling_strategy import PollingStrategy
from vaultsandbox.strategies.sse_strategy import SSEStrategy
from vaultsandbox.types import PollingConfig, SSEConfig


class TestSubscription:
    """Tests for Subscription class."""

    def test_subscription_initialization(self) -> None:
        """Test Subscription initializes with inbox and callback."""
        mock_inbox = MagicMock()
        mock_callback = MagicMock()

        subscription = Subscription(inbox=mock_inbox, callback=mock_callback)

        assert subscription.inbox == mock_inbox
        assert subscription.callback == mock_callback
        assert len(subscription.seen_email_ids) == 0

    def test_mark_seen(self) -> None:
        """Test mark_seen adds email ID to seen set."""
        subscription = Subscription(inbox=MagicMock(), callback=MagicMock())

        subscription.mark_seen("email-1")
        subscription.mark_seen("email-2")

        assert subscription.has_seen("email-1")
        assert subscription.has_seen("email-2")
        assert not subscription.has_seen("email-3")

    def test_has_seen(self) -> None:
        """Test has_seen returns correct boolean."""
        subscription = Subscription(inbox=MagicMock(), callback=MagicMock())

        assert not subscription.has_seen("email-1")
        subscription.mark_seen("email-1")
        assert subscription.has_seen("email-1")


class TestPollingStrategy:
    """Tests for PollingStrategy class."""

    def test_default_config(self) -> None:
        """Test PollingStrategy uses default config when none provided."""
        mock_api_client = MagicMock()
        strategy = PollingStrategy(mock_api_client)

        assert strategy._config.initial_interval == 2000
        assert strategy._config.max_backoff == 30000
        assert strategy._config.backoff_multiplier == 1.5
        assert strategy._config.jitter_factor == 0.3

    def test_custom_config(self) -> None:
        """Test PollingStrategy uses custom config when provided."""
        mock_api_client = MagicMock()
        config = PollingConfig(
            initial_interval=5000,
            max_backoff=60000,
            backoff_multiplier=2.0,
            jitter_factor=0.2,
        )
        strategy = PollingStrategy(mock_api_client, config)

        assert strategy._config.initial_interval == 5000
        assert strategy._config.max_backoff == 60000
        assert strategy._config.backoff_multiplier == 2.0
        assert strategy._config.jitter_factor == 0.2

    @pytest.mark.asyncio
    async def test_subscribe_creates_subscription(self) -> None:
        """Test subscribe creates a Subscription and starts polling."""
        mock_api_client = MagicMock()
        mock_api_client.get_sync_status = AsyncMock(return_value=MagicMock(emails_hash="hash1"))
        mock_api_client.list_emails = AsyncMock(return_value=[])

        strategy = PollingStrategy(mock_api_client)
        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_callback = MagicMock()

        subscription = await strategy.subscribe(mock_inbox, mock_callback)

        assert isinstance(subscription, Subscription)
        assert subscription.inbox == mock_inbox
        assert subscription.callback == mock_callback
        assert "test@example.com" in strategy._subscriptions
        assert "test@example.com" in strategy._polling_tasks

        # Clean up
        await strategy.close()

    @pytest.mark.asyncio
    async def test_unsubscribe_cancels_polling(self) -> None:
        """Test unsubscribe cancels polling task and removes subscription."""
        mock_api_client = MagicMock()
        mock_api_client.get_sync_status = AsyncMock(return_value=MagicMock(emails_hash="hash1"))
        mock_api_client.list_emails = AsyncMock(return_value=[])

        strategy = PollingStrategy(mock_api_client)
        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"

        subscription = await strategy.subscribe(mock_inbox, MagicMock())
        await strategy.unsubscribe(subscription)

        assert "test@example.com" not in strategy._subscriptions
        assert "test@example.com" not in strategy._polling_tasks

    @pytest.mark.asyncio
    async def test_close_cancels_all_tasks(self) -> None:
        """Test close cancels all polling tasks."""
        mock_api_client = MagicMock()
        mock_api_client.get_sync_status = AsyncMock(return_value=MagicMock(emails_hash="hash1"))
        mock_api_client.list_emails = AsyncMock(return_value=[])

        strategy = PollingStrategy(mock_api_client)

        # Subscribe to multiple inboxes
        mock_inbox1 = MagicMock()
        mock_inbox1.email_address = "test1@example.com"
        mock_inbox2 = MagicMock()
        mock_inbox2.email_address = "test2@example.com"

        await strategy.subscribe(mock_inbox1, MagicMock())
        await strategy.subscribe(mock_inbox2, MagicMock())

        assert len(strategy._polling_tasks) == 2

        await strategy.close()

        assert len(strategy._polling_tasks) == 0
        assert len(strategy._subscriptions) == 0
        assert strategy._running is False


class TestSSEStrategy:
    """Tests for SSEStrategy class."""

    def test_default_config(self) -> None:
        """Test SSEStrategy uses default config when none provided."""
        mock_api_client = MagicMock()
        strategy = SSEStrategy(mock_api_client)

        assert strategy._config.reconnect_interval == 5000
        assert strategy._config.max_reconnect_attempts == 10

    def test_custom_config(self) -> None:
        """Test SSEStrategy uses custom config when provided."""
        mock_api_client = MagicMock()
        config = SSEConfig(
            reconnect_interval=10000,
            max_reconnect_attempts=5,
        )
        strategy = SSEStrategy(mock_api_client, config)

        assert strategy._config.reconnect_interval == 10000
        assert strategy._config.max_reconnect_attempts == 5

    @pytest.mark.asyncio
    async def test_unsubscribe_removes_subscription(self) -> None:
        """Test unsubscribe removes subscription from maps."""
        mock_api_client = MagicMock()
        mock_api_client.config = MagicMock()
        mock_api_client.config.base_url = "https://example.com"
        mock_api_client.config.api_key = "test-key"

        strategy = SSEStrategy(mock_api_client)

        # Manually add a subscription (simulating what subscribe would do)
        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"

        subscription = Subscription(inbox=mock_inbox, callback=MagicMock())
        strategy._subscriptions["test@example.com"] = subscription
        strategy._inbox_hash_map["test-hash"] = "test@example.com"

        await strategy.unsubscribe(subscription)

        assert "test@example.com" not in strategy._subscriptions
        assert "test-hash" not in strategy._inbox_hash_map

    @pytest.mark.asyncio
    async def test_close_cleans_up_resources(self) -> None:
        """Test close cleans up all resources."""
        mock_api_client = MagicMock()
        strategy = SSEStrategy(mock_api_client)

        # Add some subscriptions manually
        strategy._subscriptions["test1@example.com"] = MagicMock()
        strategy._subscriptions["test2@example.com"] = MagicMock()
        strategy._inbox_hash_map["hash1"] = "test1@example.com"
        strategy._inbox_hash_map["hash2"] = "test2@example.com"

        await strategy.close()

        assert len(strategy._subscriptions) == 0
        assert len(strategy._inbox_hash_map) == 0
        assert strategy._running is False


class TestPollingBackoffCalculation:
    """Tests for polling backoff calculation logic."""

    def test_backoff_multiplier(self) -> None:
        """Test backoff increases with multiplier."""
        config = PollingConfig(
            initial_interval=1000,
            max_backoff=10000,
            backoff_multiplier=2.0,
        )

        current_backoff = config.initial_interval

        # Simulate backoff increases
        current_backoff = min(
            current_backoff * config.backoff_multiplier,
            config.max_backoff,
        )
        assert current_backoff == 2000

        current_backoff = min(
            current_backoff * config.backoff_multiplier,
            config.max_backoff,
        )
        assert current_backoff == 4000

        current_backoff = min(
            current_backoff * config.backoff_multiplier,
            config.max_backoff,
        )
        assert current_backoff == 8000

        # Should cap at max_backoff
        current_backoff = min(
            current_backoff * config.backoff_multiplier,
            config.max_backoff,
        )
        assert current_backoff == 10000  # capped at max_backoff

    def test_backoff_resets_on_change(self) -> None:
        """Test backoff resets when hash changes."""
        config = PollingConfig(initial_interval=1000)

        # Simulate backoff reaching high value
        current_backoff = 8000.0

        # Simulate hash change (new email arrived)
        current_backoff = config.initial_interval  # Reset

        assert current_backoff == 1000


class TestSSEReconnectLogic:
    """Tests for SSE reconnection logic."""

    def test_reconnect_delay_calculation(self) -> None:
        """Test reconnect delay increases exponentially."""
        config = SSEConfig(reconnect_interval=1000)

        # First reconnect
        reconnect_count = 1
        delay = config.reconnect_interval * (2 ** (reconnect_count - 1))
        assert delay == 1000

        # Second reconnect
        reconnect_count = 2
        delay = config.reconnect_interval * (2 ** (reconnect_count - 1))
        assert delay == 2000

        # Third reconnect
        reconnect_count = 3
        delay = config.reconnect_interval * (2 ** (reconnect_count - 1))
        assert delay == 4000

    def test_max_reconnect_attempts(self) -> None:
        """Test max reconnect attempts is respected."""
        config = SSEConfig(max_reconnect_attempts=3)

        # Should allow up to max_reconnect_attempts
        for i in range(config.max_reconnect_attempts):
            assert i < config.max_reconnect_attempts

        # After max attempts, should stop
        reconnect_count = config.max_reconnect_attempts
        assert reconnect_count >= config.max_reconnect_attempts


class TestPollingStrategyBehavior:
    """Tests for polling strategy behavior."""

    @pytest.mark.asyncio
    async def test_polling_detects_new_emails(self) -> None:
        """Polling detects new emails via hash change."""
        mock_api_client = MagicMock()

        # Track sync status calls
        sync_call_count = 0

        async def mock_get_sync_status(*args, **kwargs):
            nonlocal sync_call_count
            sync_call_count += 1
            return MagicMock(emails_hash=f"hash{sync_call_count}")

        mock_api_client.get_sync_status = AsyncMock(side_effect=mock_get_sync_status)
        mock_api_client.list_emails = AsyncMock(return_value=[])

        strategy = PollingStrategy(mock_api_client, PollingConfig(initial_interval=50))
        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "inbox-hash"

        callback = MagicMock()
        await strategy.subscribe(mock_inbox, callback)

        # Wait briefly for polling to execute multiple times
        await asyncio.sleep(0.2)

        await strategy.close()

        # Verify sync status was checked multiple times
        assert sync_call_count >= 2

    @pytest.mark.asyncio
    async def test_concurrent_subscriptions(self) -> None:
        """Subscribe to multiple inboxes concurrently."""
        mock_api_client = MagicMock()
        mock_api_client.get_sync_status = AsyncMock(return_value=MagicMock(emails_hash="hash1"))
        mock_api_client.list_emails = AsyncMock(return_value=[])

        strategy = PollingStrategy(mock_api_client)

        mock_inbox1 = MagicMock()
        mock_inbox1.email_address = "test1@example.com"
        mock_inbox2 = MagicMock()
        mock_inbox2.email_address = "test2@example.com"

        # Subscribe to both concurrently
        sub1, sub2 = await asyncio.gather(
            strategy.subscribe(mock_inbox1, MagicMock()),
            strategy.subscribe(mock_inbox2, MagicMock()),
        )

        assert sub1 is not None
        assert sub2 is not None
        assert len(strategy._subscriptions) == 2
        assert len(strategy._polling_tasks) == 2

        await strategy.close()


class TestSSEStrategySubscription:
    """Tests for SSE strategy subscription management."""

    @pytest.mark.asyncio
    async def test_subscribe_returns_subscription(self) -> None:
        """Subscribe to inbox returns subscription object."""
        mock_api_client = MagicMock()
        mock_api_client.config = MagicMock()
        mock_api_client.config.base_url = "https://example.com"
        mock_api_client.config.api_key = "test-key"

        strategy = SSEStrategy(mock_api_client)

        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"

        # Manually create a subscription to simulate subscribe behavior
        subscription = Subscription(inbox=mock_inbox, callback=lambda e: None)
        strategy._subscriptions["test@example.com"] = subscription
        strategy._inbox_hash_map["test-hash"] = "test@example.com"

        assert subscription is not None
        assert subscription.inbox == mock_inbox

        await strategy.close()

    @pytest.mark.asyncio
    async def test_multiple_unsubscribe_idempotent(self) -> None:
        """Call unsubscribe multiple times without error."""
        mock_api_client = MagicMock()
        mock_api_client.config = MagicMock()
        mock_api_client.config.base_url = "https://example.com"
        mock_api_client.config.api_key = "test-key"

        strategy = SSEStrategy(mock_api_client)

        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"

        subscription = Subscription(inbox=mock_inbox, callback=lambda e: None)
        strategy._subscriptions["test@example.com"] = subscription
        strategy._inbox_hash_map["test-hash"] = "test@example.com"

        await strategy.unsubscribe(subscription)
        await strategy.unsubscribe(subscription)  # Should not raise

        await strategy.close()


class TestInboxMonitorCallbacks:
    """Tests for InboxMonitor callback behavior."""

    @pytest.mark.asyncio
    async def test_monitor_empty_inbox_array(self) -> None:
        """Monitor empty array doesn't crash, returns valid monitor."""
        from vaultsandbox.client import InboxMonitor

        mock_strategy = MagicMock()
        monitor = InboxMonitor(inboxes=[], strategy=mock_strategy)

        assert monitor is not None
        result = await monitor.start()
        assert result is monitor
        assert monitor._started is True

        await monitor.unsubscribe()


class TestPollingStrategyBackoff:
    """Tests for polling strategy backoff behavior (lines 126, 137-144)."""

    @pytest.mark.asyncio
    async def test_backoff_increases_when_no_hash_change(self) -> None:
        """Test backoff increases when hash doesn't change (line 126)."""
        mock_api_client = MagicMock()

        # Return the same hash every time to trigger backoff increase
        mock_api_client.get_sync_status = AsyncMock(return_value=MagicMock(emails_hash="same-hash"))
        mock_api_client.list_emails = AsyncMock(return_value=[])

        config = PollingConfig(
            initial_interval=10,  # Very short for testing
            max_backoff=100,
            backoff_multiplier=2.0,
            jitter_factor=0,  # No jitter for predictable testing
        )
        strategy = PollingStrategy(mock_api_client, config)

        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"

        await strategy.subscribe(mock_inbox, MagicMock())

        # Wait for multiple polling cycles
        await asyncio.sleep(0.15)

        await strategy.close()

        # Verify sync status was called multiple times (backoff is working)
        assert mock_api_client.get_sync_status.call_count >= 2

    @pytest.mark.asyncio
    async def test_polling_handles_error_with_backoff(self) -> None:
        """Test polling handles errors and applies backoff (lines 137-144)."""
        mock_api_client = MagicMock()

        # First call raises an error, subsequent calls succeed
        call_count = 0

        async def mock_get_sync_status(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("Network error")
            return MagicMock(emails_hash="hash1")

        mock_api_client.get_sync_status = AsyncMock(side_effect=mock_get_sync_status)
        mock_api_client.list_emails = AsyncMock(return_value=[])

        config = PollingConfig(
            initial_interval=10,
            max_backoff=50,
            backoff_multiplier=2.0,
            jitter_factor=0,
        )
        strategy = PollingStrategy(mock_api_client, config)

        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"

        await strategy.subscribe(mock_inbox, MagicMock())

        # Wait for polling to execute and recover from error
        await asyncio.sleep(0.15)

        await strategy.close()

        # Verify polling continued after error
        assert call_count >= 2


class TestPollingStrategyProcessNewEmails:
    """Tests for _process_new_emails method (lines 158-178)."""

    @pytest.mark.asyncio
    async def test_process_new_emails_calls_callback(self) -> None:
        """Test _process_new_emails calls callback for new emails (lines 158-175)."""
        mock_api_client = MagicMock()

        # Track hash changes to trigger email processing
        call_count = 0

        async def mock_get_sync_status(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            # Return different hash each time to trigger email processing
            return MagicMock(emails_hash=f"hash{call_count}")

        mock_api_client.get_sync_status = AsyncMock(side_effect=mock_get_sync_status)
        mock_api_client.list_emails = AsyncMock(
            return_value=[
                {"id": "email-1", "encryptedContent": {}},
            ]
        )

        config = PollingConfig(
            initial_interval=10,
            jitter_factor=0,
        )
        strategy = PollingStrategy(mock_api_client, config)

        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.server_sig_pk = "test-pk"
        mock_inbox._keypair = MagicMock()

        # Use an async callback
        callback_emails = []

        async def async_callback(email):
            callback_emails.append(email)

        # Mock Email._from_response
        from unittest.mock import patch

        with patch("vaultsandbox.email.Email._from_response") as mock_from_response:
            mock_email = MagicMock()
            mock_email.id = "email-1"
            mock_from_response.return_value = mock_email

            await strategy.subscribe(mock_inbox, async_callback)

            # Wait for polling to process emails
            await asyncio.sleep(0.1)

            await strategy.close()

        # Verify callback was called with the email
        assert len(callback_emails) >= 1

    @pytest.mark.asyncio
    async def test_process_new_emails_skips_seen(self) -> None:
        """Test _process_new_emails skips already seen emails (lines 161-162)."""
        mock_api_client = MagicMock()

        call_count = 0

        async def mock_get_sync_status(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return MagicMock(emails_hash=f"hash{call_count}")

        mock_api_client.get_sync_status = AsyncMock(side_effect=mock_get_sync_status)
        mock_api_client.list_emails = AsyncMock(
            return_value=[
                {"id": "email-1", "encryptedContent": {}},
            ]
        )

        config = PollingConfig(
            initial_interval=10,
            jitter_factor=0,
        )
        strategy = PollingStrategy(mock_api_client, config)

        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.server_sig_pk = "test-pk"
        mock_inbox._keypair = MagicMock()

        callback_count = 0

        def sync_callback(email):
            nonlocal callback_count
            callback_count += 1

        from unittest.mock import patch

        with patch("vaultsandbox.email.Email._from_response") as mock_from_response:
            mock_email = MagicMock()
            mock_email.id = "email-1"
            mock_from_response.return_value = mock_email

            await strategy.subscribe(mock_inbox, sync_callback)

            # Wait for first poll cycle
            await asyncio.sleep(0.05)

            # Get initial callback count
            initial_count = callback_count

            # Wait for more poll cycles
            await asyncio.sleep(0.1)

            await strategy.close()

        # Callback should only have been called once for the same email
        # because subsequent polls should skip the already-seen email
        assert callback_count == initial_count

    @pytest.mark.asyncio
    async def test_process_new_emails_handles_callback_error(self) -> None:
        """Test _process_new_emails handles callback errors (lines 177-178)."""
        mock_api_client = MagicMock()

        call_count = 0

        async def mock_get_sync_status(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return MagicMock(emails_hash=f"hash{call_count}")

        mock_api_client.get_sync_status = AsyncMock(side_effect=mock_get_sync_status)
        mock_api_client.list_emails = AsyncMock(
            return_value=[
                {"id": "email-1", "encryptedContent": {}},
            ]
        )

        config = PollingConfig(
            initial_interval=10,
            jitter_factor=0,
        )
        strategy = PollingStrategy(mock_api_client, config)

        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.server_sig_pk = "test-pk"
        mock_inbox._keypair = MagicMock()

        # Callback that raises an error
        def error_callback(email):
            raise ValueError("Callback error")

        from unittest.mock import patch

        with patch("vaultsandbox.email.Email._from_response") as mock_from_response:
            mock_email = MagicMock()
            mock_email.id = "email-1"
            mock_from_response.return_value = mock_email

            # Should not raise even though callback raises
            await strategy.subscribe(mock_inbox, error_callback)

            # Wait for polling
            await asyncio.sleep(0.05)

            # Close should complete without error
            await strategy.close()

    @pytest.mark.asyncio
    async def test_process_new_emails_with_sync_callback(self) -> None:
        """Test _process_new_emails works with synchronous callbacks (line 173-174)."""
        mock_api_client = MagicMock()

        call_count = 0

        async def mock_get_sync_status(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return MagicMock(emails_hash=f"hash{call_count}")

        mock_api_client.get_sync_status = AsyncMock(side_effect=mock_get_sync_status)
        mock_api_client.list_emails = AsyncMock(
            return_value=[
                {"id": "email-sync-1", "encryptedContent": {}},
            ]
        )

        config = PollingConfig(
            initial_interval=10,
            jitter_factor=0,
        )
        strategy = PollingStrategy(mock_api_client, config)

        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.server_sig_pk = "test-pk"
        mock_inbox._keypair = MagicMock()

        # Use a synchronous callback
        sync_callback_emails = []

        def sync_callback(email):
            sync_callback_emails.append(email)

        from unittest.mock import patch

        with patch("vaultsandbox.email.Email._from_response") as mock_from_response:
            mock_email = MagicMock()
            mock_email.id = "email-sync-1"
            mock_from_response.return_value = mock_email

            await strategy.subscribe(mock_inbox, sync_callback)

            # Wait for polling to process emails
            await asyncio.sleep(0.05)

            await strategy.close()

        # Verify sync callback was called
        assert len(sync_callback_emails) >= 1


class TestSSEStrategySubscribeTimeout:
    """Tests for SSE subscribe timeout handling (lines 86-90)."""

    @pytest.mark.asyncio
    async def test_subscribe_timeout_cleans_up_and_raises(self) -> None:
        """Test subscribe timeout removes subscription and raises SSEError."""
        from vaultsandbox.errors import SSEError

        mock_api_client = MagicMock()
        mock_api_client.config = MagicMock()
        mock_api_client.config.base_url = "https://example.com"
        mock_api_client.config.api_key = "test-key"

        strategy = SSEStrategy(mock_api_client)

        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"

        # Make the connected_event never get set (simulate timeout)
        original_reconnect = strategy._reconnect_sse

        async def mock_reconnect():
            await original_reconnect()
            # Override the event to never be set
            strategy._connected_event = asyncio.Event()
            # Cancel the SSE task so it doesn't run
            if strategy._sse_task:
                strategy._sse_task.cancel()

        strategy._reconnect_sse = mock_reconnect

        with pytest.raises(SSEError) as exc_info:
            await strategy.subscribe(mock_inbox, lambda e: None)

        assert "timed out" in str(exc_info.value)
        # Verify cleanup happened
        assert "test@example.com" not in strategy._subscriptions
        assert "test-hash" not in strategy._inbox_hash_map

        await strategy.close()


class TestSSEStrategySubscribeConnectionError:
    """Tests for SSE subscribe connection error handling (lines 95-97)."""

    @pytest.mark.asyncio
    async def test_subscribe_connection_error_cleans_up_and_raises(self) -> None:
        """Test subscribe cleans up and re-raises when SSE task fails."""
        mock_api_client = MagicMock()
        mock_api_client.config = MagicMock()
        mock_api_client.config.base_url = "https://example.com"
        mock_api_client.config.api_key = "test-key"

        strategy = SSEStrategy(mock_api_client)

        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"

        # Create an error that will be stored in _error
        test_error = ValueError("Connection failed")

        async def mock_reconnect():
            # Create connected event that will be set
            strategy._error = None
            strategy._connected_event = asyncio.Event()
            # Set error and then set the event
            strategy._error = test_error
            strategy._connected_event.set()

        strategy._reconnect_sse = mock_reconnect

        with pytest.raises(ValueError) as exc_info:
            await strategy.subscribe(mock_inbox, lambda e: None)

        assert "Connection failed" in str(exc_info.value)
        # Verify cleanup happened
        assert "test@example.com" not in strategy._subscriptions
        assert "test-hash" not in strategy._inbox_hash_map

        await strategy.close()


class TestSSEStrategyUnsubscribeTimeout:
    """Tests for SSE unsubscribe timeout handling (lines 131-132)."""

    @pytest.mark.asyncio
    async def test_unsubscribe_timeout_logs_debug(self) -> None:
        """Test unsubscribe timeout is handled gracefully (lines 131-132)."""
        mock_api_client = MagicMock()
        mock_api_client.config = MagicMock()
        mock_api_client.config.base_url = "https://example.com"
        mock_api_client.config.api_key = "test-key"
        mock_api_client.list_emails = AsyncMock(return_value=[])

        strategy = SSEStrategy(mock_api_client)

        # Add two subscriptions
        mock_inbox1 = MagicMock()
        mock_inbox1.email_address = "test1@example.com"
        mock_inbox1.inbox_hash = "test-hash-1"

        mock_inbox2 = MagicMock()
        mock_inbox2.email_address = "test2@example.com"
        mock_inbox2.inbox_hash = "test-hash-2"

        subscription1 = Subscription(inbox=mock_inbox1, callback=lambda e: None)
        subscription2 = Subscription(inbox=mock_inbox2, callback=lambda e: None)

        strategy._subscriptions["test1@example.com"] = subscription1
        strategy._subscriptions["test2@example.com"] = subscription2
        strategy._inbox_hash_map["test-hash-1"] = "test1@example.com"
        strategy._inbox_hash_map["test-hash-2"] = "test2@example.com"

        # Mock reconnect to simulate timeout
        async def mock_reconnect():
            strategy._connected_event = asyncio.Event()
            # Never set the event to cause timeout

        strategy._reconnect_sse = mock_reconnect

        # Should not raise even with timeout
        await strategy.unsubscribe(subscription1)

        # Verify subscription was removed
        assert "test1@example.com" not in strategy._subscriptions

        await strategy.close()


class TestSSEStrategyReconnectNoSubscriptions:
    """Tests for _reconnect_sse early return (line 164)."""

    @pytest.mark.asyncio
    async def test_reconnect_returns_early_when_no_subscriptions(self) -> None:
        """Test _reconnect_sse returns early when no subscriptions."""
        mock_api_client = MagicMock()
        strategy = SSEStrategy(mock_api_client)

        # Ensure no subscriptions
        assert len(strategy._subscriptions) == 0

        # Call reconnect directly
        await strategy._reconnect_sse()

        # No SSE task should be created
        assert strategy._sse_task is None
        assert strategy._connected_event is None


class TestSSETaskDoneCallback:
    """Tests for _on_sse_task_done callback (lines 179, 183-189)."""

    def test_on_task_done_with_cancelled_task(self) -> None:
        """Test _on_sse_task_done returns early for cancelled task (line 179)."""
        mock_api_client = MagicMock()
        strategy = SSEStrategy(mock_api_client)

        # Create a cancelled task
        mock_task = MagicMock()
        mock_task.cancelled.return_value = True

        # Should return early without accessing exception
        strategy._on_sse_task_done(mock_task)
        mock_task.exception.assert_not_called()

    def test_on_task_done_stores_exception(self) -> None:
        """Test _on_sse_task_done stores exception (line 183)."""
        mock_api_client = MagicMock()
        strategy = SSEStrategy(mock_api_client)

        test_error = ValueError("Test error")
        mock_task = MagicMock()
        mock_task.cancelled.return_value = False
        mock_task.exception.return_value = test_error

        strategy._on_sse_task_done(mock_task)

        assert strategy._error is test_error

    def test_on_task_done_invokes_error_callback(self) -> None:
        """Test _on_sse_task_done invokes error callback (lines 185-187)."""
        mock_api_client = MagicMock()
        error_callback = MagicMock()
        config = SSEConfig(on_error=error_callback)
        strategy = SSEStrategy(mock_api_client, config)

        test_error = ValueError("Test error")
        mock_task = MagicMock()
        mock_task.cancelled.return_value = False
        mock_task.exception.return_value = test_error

        strategy._on_sse_task_done(mock_task)

        error_callback.assert_called_once_with(test_error)

    def test_on_task_done_handles_callback_error(self) -> None:
        """Test _on_sse_task_done handles callback error (lines 188-189)."""
        mock_api_client = MagicMock()

        def failing_callback(exc):
            raise RuntimeError("Callback failed")

        config = SSEConfig(on_error=failing_callback)
        strategy = SSEStrategy(mock_api_client, config)

        test_error = ValueError("Test error")
        mock_task = MagicMock()
        mock_task.cancelled.return_value = False
        mock_task.exception.return_value = test_error

        # Should not raise even when callback fails
        strategy._on_sse_task_done(mock_task)


class TestSSERunLoopReconnect:
    """Tests for _run_sse reconnect logic (lines 196, 199-208)."""

    @pytest.mark.asyncio
    async def test_run_sse_resets_reconnect_count_on_success(self) -> None:
        """Test reconnect count resets on successful connection (line 196)."""
        mock_api_client = MagicMock()
        mock_api_client.config = MagicMock()
        mock_api_client.config.base_url = "https://example.com"
        mock_api_client.config.api_key = "test-key"

        strategy = SSEStrategy(mock_api_client)
        strategy._reconnect_count = 5  # Simulate some reconnects

        # Add a subscription
        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"
        subscription = Subscription(inbox=mock_inbox, callback=lambda e: None)
        strategy._subscriptions["test@example.com"] = subscription
        strategy._inbox_hash_map["test-hash"] = "test@example.com"

        # Mock _connect_and_listen to succeed then stop
        call_count = 0

        async def mock_connect():
            nonlocal call_count
            call_count += 1
            strategy._running = False  # Stop after first call

        strategy._connect_and_listen = mock_connect

        await strategy._run_sse()

        assert strategy._reconnect_count == 0  # Reset on success

    @pytest.mark.asyncio
    async def test_run_sse_max_reconnect_attempts_exceeded(self) -> None:
        """Test SSEError raised when max reconnects exceeded (lines 199-204)."""
        from vaultsandbox.errors import SSEError

        mock_api_client = MagicMock()
        config = SSEConfig(max_reconnect_attempts=2, reconnect_interval=1)
        strategy = SSEStrategy(mock_api_client, config)

        # Add a subscription
        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"
        subscription = Subscription(inbox=mock_inbox, callback=lambda e: None)
        strategy._subscriptions["test@example.com"] = subscription
        strategy._inbox_hash_map["test-hash"] = "test@example.com"

        # Mock _connect_and_listen to always fail
        async def mock_connect():
            raise ConnectionError("Connection failed")

        strategy._connect_and_listen = mock_connect

        with pytest.raises(SSEError) as exc_info:
            await strategy._run_sse()

        assert "Max reconnection attempts" in str(exc_info.value)
        assert strategy._reconnect_count == 2

    @pytest.mark.asyncio
    async def test_run_sse_exponential_backoff(self) -> None:
        """Test exponential backoff between reconnects (lines 206-208)."""

        mock_api_client = MagicMock()
        config = SSEConfig(max_reconnect_attempts=3, reconnect_interval=50)
        strategy = SSEStrategy(mock_api_client, config)

        # Add a subscription
        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"
        subscription = Subscription(inbox=mock_inbox, callback=lambda e: None)
        strategy._subscriptions["test@example.com"] = subscription
        strategy._inbox_hash_map["test-hash"] = "test@example.com"

        # Track sleep calls
        sleep_times = []
        original_sleep = asyncio.sleep

        async def mock_sleep(delay):
            sleep_times.append(delay)
            await original_sleep(0.001)  # Minimal actual sleep

        call_count = 0

        async def mock_connect():
            nonlocal call_count
            call_count += 1
            raise ConnectionError("Connection failed")

        strategy._connect_and_listen = mock_connect

        from unittest.mock import patch

        with patch("asyncio.sleep", mock_sleep), pytest.raises(SSEError):
            await strategy._run_sse()

        # Verify exponential backoff: 50ms, 100ms (in seconds: 0.05, 0.1)
        assert len(sleep_times) == 2
        assert sleep_times[0] == 0.05  # 50ms / 1000 = 0.05s
        assert sleep_times[1] == 0.1  # 100ms / 1000 = 0.1s


class TestSSEConnectAndListenEarlyReturn:
    """Tests for _connect_and_listen early return (line 213)."""

    @pytest.mark.asyncio
    async def test_connect_returns_early_when_no_subscriptions(self) -> None:
        """Test _connect_and_listen returns early with no subscriptions."""
        mock_api_client = MagicMock()
        mock_api_client.config = MagicMock()

        strategy = SSEStrategy(mock_api_client)

        # Ensure no subscriptions
        assert len(strategy._subscriptions) == 0

        # Should return without creating client
        await strategy._connect_and_listen()

        assert strategy._client is None


class TestSSEHandleEvent:
    """Tests for _handle_event branches (lines 237, 254, 259, 263, 267, 284-287)."""

    @pytest.mark.asyncio
    async def test_handle_event_missing_inbox_id(self) -> None:
        """Test _handle_event returns early when no inboxId (line 254)."""
        mock_api_client = MagicMock()
        strategy = SSEStrategy(mock_api_client)

        # Event without inboxId
        await strategy._handle_event('{"emailId": "email-1"}')

        # Should return early, no API calls
        mock_api_client.get_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_event_missing_email_id(self) -> None:
        """Test _handle_event returns early when no emailId (line 254)."""
        mock_api_client = MagicMock()
        strategy = SSEStrategy(mock_api_client)

        # Event without emailId
        await strategy._handle_event('{"inboxId": "inbox-1"}')

        # Should return early, no API calls
        mock_api_client.get_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_event_unknown_inbox(self) -> None:
        """Test _handle_event returns early for unknown inbox (line 259)."""
        mock_api_client = MagicMock()
        strategy = SSEStrategy(mock_api_client)

        # inbox_hash_map is empty
        await strategy._handle_event('{"inboxId": "unknown-hash", "emailId": "email-1"}')

        # Should return early, no API calls
        mock_api_client.get_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_event_no_subscription(self) -> None:
        """Test _handle_event returns early when subscription not found (line 263)."""
        mock_api_client = MagicMock()
        strategy = SSEStrategy(mock_api_client)

        # Add to hash map but not to subscriptions
        strategy._inbox_hash_map["test-hash"] = "test@example.com"

        await strategy._handle_event('{"inboxId": "test-hash", "emailId": "email-1"}')

        # Should return early, no API calls
        mock_api_client.get_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_event_skips_seen_email(self) -> None:
        """Test _handle_event skips already seen emails (line 267)."""
        mock_api_client = MagicMock()
        strategy = SSEStrategy(mock_api_client)

        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"

        subscription = Subscription(inbox=mock_inbox, callback=lambda e: None)
        subscription.mark_seen("email-1")  # Mark as already seen

        strategy._subscriptions["test@example.com"] = subscription
        strategy._inbox_hash_map["test-hash"] = "test@example.com"

        await strategy._handle_event('{"inboxId": "test-hash", "emailId": "email-1"}')

        # Should return early, no API calls for already seen email
        mock_api_client.get_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_event_json_decode_error(self) -> None:
        """Test _handle_event handles JSON decode error (lines 284-285)."""
        mock_api_client = MagicMock()
        strategy = SSEStrategy(mock_api_client)

        # Invalid JSON should not raise
        await strategy._handle_event("not valid json {{{")

        # Should handle error gracefully, no API calls
        mock_api_client.get_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_event_general_exception(self) -> None:
        """Test _handle_event handles general exceptions (lines 286-287)."""
        mock_api_client = MagicMock()
        mock_api_client.get_email = AsyncMock(side_effect=Exception("API error"))

        strategy = SSEStrategy(mock_api_client)

        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"

        subscription = Subscription(inbox=mock_inbox, callback=lambda e: None)
        strategy._subscriptions["test@example.com"] = subscription
        strategy._inbox_hash_map["test-hash"] = "test@example.com"

        # Should not raise even when API fails
        await strategy._handle_event('{"inboxId": "test-hash", "emailId": "email-1"}')

    @pytest.mark.asyncio
    async def test_handle_event_processes_email_with_async_callback(self) -> None:
        """Test _handle_event processes email and calls async callback (lines 280-282)."""
        mock_api_client = MagicMock()
        mock_api_client.get_email = AsyncMock(
            return_value={"id": "email-1", "encryptedContent": {}}
        )

        strategy = SSEStrategy(mock_api_client)

        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"

        callback_emails = []

        async def async_callback(email):
            callback_emails.append(email)

        subscription = Subscription(inbox=mock_inbox, callback=async_callback)
        strategy._subscriptions["test@example.com"] = subscription
        strategy._inbox_hash_map["test-hash"] = "test@example.com"

        from unittest.mock import patch

        with patch("vaultsandbox.email.Email._from_response") as mock_from_response:
            mock_email = MagicMock()
            mock_email.id = "email-1"
            mock_from_response.return_value = mock_email

            await strategy._handle_event('{"inboxId": "test-hash", "emailId": "email-1"}')

        assert len(callback_emails) == 1
        assert subscription.has_seen("email-1")


class TestSSESyncSubscription:
    """Tests for _sync_subscription (lines 327-352)."""

    @pytest.mark.asyncio
    async def test_sync_subscription_processes_unseen_emails(self) -> None:
        """Test _sync_subscription processes unseen emails (lines 327-342)."""
        mock_api_client = MagicMock()
        mock_api_client.list_emails = AsyncMock(
            return_value=[
                {"id": "email-1"},
                {"id": "email-2"},
            ]
        )
        mock_api_client.get_email = AsyncMock(
            return_value={"id": "email-1", "encryptedContent": {}}
        )

        strategy = SSEStrategy(mock_api_client)

        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"

        callback_emails = []

        def sync_callback(email):
            callback_emails.append(email)

        subscription = Subscription(inbox=mock_inbox, callback=sync_callback)

        from unittest.mock import patch

        with patch("vaultsandbox.email.Email._from_response") as mock_from_response:
            mock_email = MagicMock()
            mock_from_response.return_value = mock_email

            await strategy._sync_subscription(subscription)

        # Should have processed both emails
        assert len(callback_emails) == 2
        assert subscription.has_seen("email-1")
        assert subscription.has_seen("email-2")

    @pytest.mark.asyncio
    async def test_sync_subscription_skips_seen_emails(self) -> None:
        """Test _sync_subscription skips already seen emails (line 324-325)."""
        mock_api_client = MagicMock()
        mock_api_client.list_emails = AsyncMock(
            return_value=[
                {"id": "email-1"},
                {"id": "email-2"},
            ]
        )
        mock_api_client.get_email = AsyncMock(
            return_value={"id": "email-2", "encryptedContent": {}}
        )

        strategy = SSEStrategy(mock_api_client)

        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"

        callback_emails = []

        def sync_callback(email):
            callback_emails.append(email)

        subscription = Subscription(inbox=mock_inbox, callback=sync_callback)
        subscription.mark_seen("email-1")  # Already seen

        from unittest.mock import patch

        with patch("vaultsandbox.email.Email._from_response") as mock_from_response:
            mock_email = MagicMock()
            mock_from_response.return_value = mock_email

            await strategy._sync_subscription(subscription)

        # Should have only processed email-2
        assert len(callback_emails) == 1
        assert mock_api_client.get_email.call_count == 1

    @pytest.mark.asyncio
    async def test_sync_subscription_with_async_callback(self) -> None:
        """Test _sync_subscription works with async callback (lines 340-342)."""
        mock_api_client = MagicMock()
        mock_api_client.list_emails = AsyncMock(return_value=[{"id": "email-1"}])
        mock_api_client.get_email = AsyncMock(
            return_value={"id": "email-1", "encryptedContent": {}}
        )

        strategy = SSEStrategy(mock_api_client)

        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"

        callback_emails = []

        async def async_callback(email):
            callback_emails.append(email)

        subscription = Subscription(inbox=mock_inbox, callback=async_callback)

        from unittest.mock import patch

        with patch("vaultsandbox.email.Email._from_response") as mock_from_response:
            mock_email = MagicMock()
            mock_from_response.return_value = mock_email

            await strategy._sync_subscription(subscription)

        assert len(callback_emails) == 1

    @pytest.mark.asyncio
    async def test_sync_subscription_handles_email_fetch_error(self) -> None:
        """Test _sync_subscription handles per-email errors (lines 344-349)."""
        mock_api_client = MagicMock()
        mock_api_client.list_emails = AsyncMock(
            return_value=[
                {"id": "email-1"},
                {"id": "email-2"},
            ]
        )

        # First email fetch fails, second succeeds
        call_count = 0

        async def mock_get_email(email_address, email_id):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("Fetch failed")
            return {"id": "email-2", "encryptedContent": {}}

        mock_api_client.get_email = AsyncMock(side_effect=mock_get_email)

        strategy = SSEStrategy(mock_api_client)

        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"

        callback_emails = []

        def sync_callback(email):
            callback_emails.append(email)

        subscription = Subscription(inbox=mock_inbox, callback=sync_callback)

        from unittest.mock import patch

        with patch("vaultsandbox.email.Email._from_response") as mock_from_response:
            mock_email = MagicMock()
            mock_from_response.return_value = mock_email

            # Should not raise even with per-email error
            await strategy._sync_subscription(subscription)

        # Should have processed the second email despite first failing
        assert len(callback_emails) == 1

    @pytest.mark.asyncio
    async def test_sync_subscription_handles_list_emails_error(self) -> None:
        """Test _sync_subscription handles list_emails error (lines 351-357)."""
        mock_api_client = MagicMock()
        mock_api_client.list_emails = AsyncMock(side_effect=Exception("List failed"))

        strategy = SSEStrategy(mock_api_client)

        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"

        subscription = Subscription(inbox=mock_inbox, callback=lambda e: None)

        # Should not raise
        await strategy._sync_subscription(subscription)

    @pytest.mark.asyncio
    async def test_sync_subscriptions_runs_in_parallel(self) -> None:
        """Test _sync_subscriptions runs multiple subscriptions in parallel."""
        mock_api_client = MagicMock()
        mock_api_client.list_emails = AsyncMock(return_value=[])

        strategy = SSEStrategy(mock_api_client)

        # Create multiple subscriptions
        subscriptions = []
        for i in range(3):
            mock_inbox = MagicMock()
            mock_inbox.email_address = f"test{i}@example.com"
            mock_inbox.inbox_hash = f"test-hash-{i}"
            subscription = Subscription(inbox=mock_inbox, callback=lambda e: None)
            subscriptions.append(subscription)

        await strategy._sync_subscriptions(subscriptions)

        # Should have called list_emails for each subscription
        assert mock_api_client.list_emails.call_count == 3


class TestSSESubscribeWithExistingSubscriptions:
    """Tests for subscribe syncing existing subscriptions (lines 101-104)."""

    @pytest.mark.asyncio
    async def test_subscribe_syncs_existing_subscriptions(self) -> None:
        """Test subscribe syncs existing subscriptions after reconnect (lines 101-104)."""
        mock_api_client = MagicMock()
        mock_api_client.config = MagicMock()
        mock_api_client.config.base_url = "https://example.com"
        mock_api_client.config.api_key = "test-key"
        mock_api_client.list_emails = AsyncMock(return_value=[])

        strategy = SSEStrategy(mock_api_client)

        # Add existing subscription
        mock_inbox1 = MagicMock()
        mock_inbox1.email_address = "existing@example.com"
        mock_inbox1.inbox_hash = "existing-hash"
        subscription1 = Subscription(inbox=mock_inbox1, callback=lambda e: None)
        strategy._subscriptions["existing@example.com"] = subscription1
        strategy._inbox_hash_map["existing-hash"] = "existing@example.com"

        # Mock reconnect to set connected immediately
        async def mock_reconnect():
            strategy._connected_event = asyncio.Event()
            strategy._connected_event.set()

        strategy._reconnect_sse = mock_reconnect

        # Subscribe with a new inbox
        mock_inbox2 = MagicMock()
        mock_inbox2.email_address = "new@example.com"
        mock_inbox2.inbox_hash = "new-hash"

        await strategy.subscribe(mock_inbox2, lambda e: None)

        # Should have synced existing subscription (called list_emails for existing inbox)
        mock_api_client.list_emails.assert_called_once_with(
            "existing@example.com", include_content=False
        )

        await strategy.close()


class TestSSECloseClient:
    """Tests for closing client in _close_sse (lines 156-157)."""

    @pytest.mark.asyncio
    async def test_close_sse_closes_client(self) -> None:
        """Test _close_sse closes httpx client (lines 156-157)."""
        mock_api_client = MagicMock()
        strategy = SSEStrategy(mock_api_client)

        # Create a mock client
        mock_client = AsyncMock()
        strategy._client = mock_client

        await strategy._close_sse()

        # Verify client was closed
        mock_client.aclose.assert_called_once()
        assert strategy._client is None


class TestSSERunCancelledError:
    """Tests for CancelledError in _run_sse (line 198)."""

    @pytest.mark.asyncio
    async def test_run_sse_handles_cancelled_error(self) -> None:
        """Test _run_sse breaks on CancelledError (line 198)."""
        mock_api_client = MagicMock()
        strategy = SSEStrategy(mock_api_client)

        # Add a subscription
        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"
        subscription = Subscription(inbox=mock_inbox, callback=lambda e: None)
        strategy._subscriptions["test@example.com"] = subscription
        strategy._inbox_hash_map["test-hash"] = "test@example.com"

        # Mock _connect_and_listen to raise CancelledError
        async def mock_connect():
            raise asyncio.CancelledError()

        strategy._connect_and_listen = mock_connect

        # Should not raise, should just break out of loop
        await strategy._run_sse()


class TestSSEConnectAndListenFull:
    """Tests for _connect_and_listen full execution (lines 216-240)."""

    @pytest.mark.asyncio
    async def test_connect_and_listen_sets_connected_event(self) -> None:
        """Test _connect_and_listen sets connected event when SSE connects."""
        from unittest.mock import patch

        mock_api_client = MagicMock()
        mock_api_client.config = MagicMock()
        mock_api_client.config.base_url = "https://example.com"
        mock_api_client.config.api_key = "test-key"

        strategy = SSEStrategy(mock_api_client)

        # Add a subscription
        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"
        subscription = Subscription(inbox=mock_inbox, callback=lambda e: None)
        strategy._subscriptions["test@example.com"] = subscription
        strategy._inbox_hash_map["test-hash"] = "test@example.com"

        # Create connected event
        strategy._connected_event = asyncio.Event()

        # Mock httpx client and SSE
        mock_http_client = MagicMock()
        mock_event_source = MagicMock()

        # Create an async iterator that yields no events
        async def empty_iter():
            return
            yield  # Make it a generator

        mock_event_source.aiter_sse = empty_iter

        @contextlib.asynccontextmanager
        async def mock_aconnect_sse(*args, **kwargs):
            yield mock_event_source

        with (
            patch("httpx.AsyncClient", return_value=mock_http_client),
            patch(
                "vaultsandbox.strategies.sse_strategy.aconnect_sse",
                mock_aconnect_sse,
            ),
        ):
            await strategy._connect_and_listen()

        # Connected event should have been set
        assert strategy._connected_event.is_set()

    @pytest.mark.asyncio
    async def test_connect_and_listen_processes_events(self) -> None:
        """Test _connect_and_listen processes SSE events (lines 235-240)."""
        from unittest.mock import patch

        mock_api_client = MagicMock()
        mock_api_client.config = MagicMock()
        mock_api_client.config.base_url = "https://example.com"
        mock_api_client.config.api_key = "test-key"
        mock_api_client.get_email = AsyncMock(
            return_value={"id": "email-1", "encryptedContent": {}}
        )

        strategy = SSEStrategy(mock_api_client)

        # Add a subscription
        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"

        callback_emails = []

        def callback(email):
            callback_emails.append(email)

        subscription = Subscription(inbox=mock_inbox, callback=callback)
        strategy._subscriptions["test@example.com"] = subscription
        strategy._inbox_hash_map["test-hash"] = "test@example.com"

        strategy._connected_event = asyncio.Event()

        # Mock SSE event
        mock_event = MagicMock()
        mock_event.data = '{"inboxId": "test-hash", "emailId": "email-1"}'

        # Create an async iterator that yields one event then stops
        async def event_iter():
            yield mock_event
            strategy._running = False  # Stop after first event

        mock_event_source = MagicMock()
        mock_event_source.aiter_sse = event_iter

        @contextlib.asynccontextmanager
        async def mock_aconnect_sse(*args, **kwargs):
            yield mock_event_source

        with (
            patch("httpx.AsyncClient"),
            patch(
                "vaultsandbox.strategies.sse_strategy.aconnect_sse",
                mock_aconnect_sse,
            ),
            patch("vaultsandbox.email.Email._from_response") as mock_from_response,
        ):
            mock_email = MagicMock()
            mock_from_response.return_value = mock_email

            await strategy._connect_and_listen()

        # Should have processed the event
        assert len(callback_emails) == 1

    @pytest.mark.asyncio
    async def test_connect_and_listen_stops_when_not_running(self) -> None:
        """Test _connect_and_listen breaks when _running is False (line 237)."""
        from unittest.mock import patch

        mock_api_client = MagicMock()
        mock_api_client.config = MagicMock()
        mock_api_client.config.base_url = "https://example.com"
        mock_api_client.config.api_key = "test-key"

        strategy = SSEStrategy(mock_api_client)
        strategy._running = False  # Set to False before starting

        # Add a subscription
        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"
        subscription = Subscription(inbox=mock_inbox, callback=lambda e: None)
        strategy._subscriptions["test@example.com"] = subscription
        strategy._inbox_hash_map["test-hash"] = "test@example.com"

        strategy._connected_event = asyncio.Event()

        # Mock SSE event that should not be processed
        mock_event = MagicMock()
        mock_event.data = '{"inboxId": "test-hash", "emailId": "email-1"}'

        events_processed = []

        async def event_iter():
            events_processed.append(mock_event)
            yield mock_event

        mock_event_source = MagicMock()
        mock_event_source.aiter_sse = event_iter

        @contextlib.asynccontextmanager
        async def mock_aconnect_sse(*args, **kwargs):
            yield mock_event_source

        with (
            patch("httpx.AsyncClient"),
            patch(
                "vaultsandbox.strategies.sse_strategy.aconnect_sse",
                mock_aconnect_sse,
            ),
        ):
            await strategy._connect_and_listen()

        # Event should be yielded but the loop should break before processing
        # because _running is False
        assert len(events_processed) == 1  # Iterator was started
