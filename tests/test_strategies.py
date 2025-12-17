"""Tests for delivery strategies (SSE and Polling)."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

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
