"""Tests for SSE concurrent operations."""

from __future__ import annotations

import asyncio
import contextlib
from unittest.mock import AsyncMock, MagicMock

import pytest

from vaultsandbox.strategies.delivery_strategy import Subscription
from vaultsandbox.strategies.sse_strategy import SSEStrategy


class TestConcurrentSubscribe:
    """Tests for concurrent subscribe operations."""

    @pytest.mark.asyncio
    async def test_concurrent_subscribe_multiple_inboxes(self) -> None:
        """Test subscribing to multiple inboxes concurrently."""
        mock_api_client = MagicMock()
        mock_api_client.config = MagicMock()
        mock_api_client.config.base_url = "https://example.com"
        mock_api_client.config.api_key = "test-key"
        mock_api_client.list_emails = AsyncMock(return_value=[])

        strategy = SSEStrategy(mock_api_client)

        # Mock reconnect to set connected immediately
        async def mock_reconnect():
            strategy._connected_event = asyncio.Event()
            strategy._connected_event.set()

        strategy._reconnect_sse = mock_reconnect

        # Create multiple mock inboxes
        inboxes = []
        for i in range(5):
            mock_inbox = MagicMock()
            mock_inbox.email_address = f"test{i}@example.com"
            mock_inbox.inbox_hash = f"test-hash-{i}"
            inboxes.append(mock_inbox)

        # Subscribe to all inboxes concurrently
        subscriptions = await asyncio.gather(
            *[strategy.subscribe(inbox, lambda e: None) for inbox in inboxes]
        )

        # Verify all subscriptions were created
        assert len(subscriptions) == 5
        assert len(strategy._subscriptions) == 5
        assert len(strategy._inbox_hash_map) == 5

        # Verify each subscription is correct
        for i, sub in enumerate(subscriptions):
            assert isinstance(sub, Subscription)
            assert sub.inbox.email_address == f"test{i}@example.com"
            assert f"test{i}@example.com" in strategy._subscriptions
            assert f"test-hash-{i}" in strategy._inbox_hash_map

        await strategy.close()

    @pytest.mark.asyncio
    async def test_concurrent_subscribe_same_inbox(self) -> None:
        """Test subscribing to the same inbox concurrently (should replace)."""
        mock_api_client = MagicMock()
        mock_api_client.config = MagicMock()
        mock_api_client.config.base_url = "https://example.com"
        mock_api_client.config.api_key = "test-key"
        mock_api_client.list_emails = AsyncMock(return_value=[])

        strategy = SSEStrategy(mock_api_client)

        # Mock reconnect to set connected with slight delay for race condition
        async def mock_reconnect():
            await asyncio.sleep(0.01)  # Small delay to encourage interleaving
            strategy._connected_event = asyncio.Event()
            strategy._connected_event.set()

        strategy._reconnect_sse = mock_reconnect

        # Same inbox subscribed multiple times
        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"

        callbacks = [MagicMock() for _ in range(3)]

        # Subscribe to same inbox concurrently with different callbacks
        await asyncio.gather(*[strategy.subscribe(mock_inbox, cb) for cb in callbacks])

        # Only one subscription should remain (last one wins)
        assert len(strategy._subscriptions) == 1
        assert len(strategy._inbox_hash_map) == 1
        assert "test@example.com" in strategy._subscriptions

        await strategy.close()


class TestSubscribeUnsubscribeRace:
    """Tests for race conditions between subscribe and unsubscribe."""

    @pytest.mark.asyncio
    async def test_subscribe_unsubscribe_rapid(self) -> None:
        """Test rapid subscribe/unsubscribe on the same inbox."""
        mock_api_client = MagicMock()
        mock_api_client.config = MagicMock()
        mock_api_client.config.base_url = "https://example.com"
        mock_api_client.config.api_key = "test-key"
        mock_api_client.list_emails = AsyncMock(return_value=[])

        strategy = SSEStrategy(mock_api_client)

        # Mock reconnect
        async def mock_reconnect():
            strategy._connected_event = asyncio.Event()
            strategy._connected_event.set()

        strategy._reconnect_sse = mock_reconnect

        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"

        # Rapid subscribe/unsubscribe cycles
        for _ in range(10):
            subscription = await strategy.subscribe(mock_inbox, lambda e: None)
            await strategy.unsubscribe(subscription)

        # After all cycles, inbox should be unsubscribed
        assert "test@example.com" not in strategy._subscriptions
        assert "test-hash" not in strategy._inbox_hash_map

        await strategy.close()

    @pytest.mark.asyncio
    async def test_concurrent_subscribe_unsubscribe(self) -> None:
        """Test concurrent subscribe and unsubscribe operations."""
        mock_api_client = MagicMock()
        mock_api_client.config = MagicMock()
        mock_api_client.config.base_url = "https://example.com"
        mock_api_client.config.api_key = "test-key"
        mock_api_client.list_emails = AsyncMock(return_value=[])

        strategy = SSEStrategy(mock_api_client)

        # Mock reconnect with small delay
        async def mock_reconnect():
            await asyncio.sleep(0.005)
            strategy._connected_event = asyncio.Event()
            strategy._connected_event.set()

        strategy._reconnect_sse = mock_reconnect

        # Create multiple inboxes
        subscriptions: list[Subscription] = []
        for i in range(5):
            mock_inbox = MagicMock()
            mock_inbox.email_address = f"test{i}@example.com"
            mock_inbox.inbox_hash = f"test-hash-{i}"
            sub = await strategy.subscribe(mock_inbox, lambda e: None)
            subscriptions.append(sub)

        # Concurrently unsubscribe from all
        await asyncio.gather(*[strategy.unsubscribe(sub) for sub in subscriptions])

        # All should be unsubscribed
        assert len(strategy._subscriptions) == 0
        assert len(strategy._inbox_hash_map) == 0

        await strategy.close()


class TestReconnectionDuringSubscribe:
    """Tests for SSE reconnection during subscribe operations."""

    @pytest.mark.asyncio
    async def test_reconnection_preserves_subscriptions(self) -> None:
        """Test that reconnection preserves existing subscriptions."""
        mock_api_client = MagicMock()
        mock_api_client.config = MagicMock()
        mock_api_client.config.base_url = "https://example.com"
        mock_api_client.config.api_key = "test-key"
        mock_api_client.list_emails = AsyncMock(return_value=[])

        strategy = SSEStrategy(mock_api_client)

        reconnect_count = 0

        async def mock_reconnect():
            nonlocal reconnect_count
            reconnect_count += 1
            strategy._connected_event = asyncio.Event()
            strategy._connected_event.set()

        strategy._reconnect_sse = mock_reconnect

        # Subscribe to first inbox
        mock_inbox1 = MagicMock()
        mock_inbox1.email_address = "test1@example.com"
        mock_inbox1.inbox_hash = "test-hash-1"
        await strategy.subscribe(mock_inbox1, lambda e: None)

        # Subscribe to second inbox (triggers reconnect)
        mock_inbox2 = MagicMock()
        mock_inbox2.email_address = "test2@example.com"
        mock_inbox2.inbox_hash = "test-hash-2"
        await strategy.subscribe(mock_inbox2, lambda e: None)

        # Both subscriptions should exist
        assert "test1@example.com" in strategy._subscriptions
        assert "test2@example.com" in strategy._subscriptions
        assert reconnect_count == 2  # Reconnect called for each subscribe

        await strategy.close()

    @pytest.mark.asyncio
    async def test_subscribe_during_reconnect(self) -> None:
        """Test subscribing while reconnection is in progress."""
        mock_api_client = MagicMock()
        mock_api_client.config = MagicMock()
        mock_api_client.config.base_url = "https://example.com"
        mock_api_client.config.api_key = "test-key"
        mock_api_client.list_emails = AsyncMock(return_value=[])

        strategy = SSEStrategy(mock_api_client)

        # Slow reconnect to simulate ongoing reconnection
        async def mock_reconnect():
            await asyncio.sleep(0.05)  # Slow reconnection
            strategy._connected_event = asyncio.Event()
            strategy._connected_event.set()

        strategy._reconnect_sse = mock_reconnect

        # Create inboxes
        mock_inbox1 = MagicMock()
        mock_inbox1.email_address = "test1@example.com"
        mock_inbox1.inbox_hash = "test-hash-1"

        mock_inbox2 = MagicMock()
        mock_inbox2.email_address = "test2@example.com"
        mock_inbox2.inbox_hash = "test-hash-2"

        # Subscribe concurrently while reconnects are slow
        sub1, sub2 = await asyncio.gather(
            strategy.subscribe(mock_inbox1, lambda e: None),
            strategy.subscribe(mock_inbox2, lambda e: None),
        )

        # Both subscriptions should succeed
        assert sub1 is not None
        assert sub2 is not None
        assert "test1@example.com" in strategy._subscriptions
        assert "test2@example.com" in strategy._subscriptions

        await strategy.close()


class TestCallbackDuringUnsubscribe:
    """Tests for callbacks arriving during unsubscribe."""

    @pytest.mark.asyncio
    async def test_callback_skipped_after_unsubscribe(self) -> None:
        """Test that callbacks are skipped for unsubscribed inboxes."""
        mock_api_client = MagicMock()
        mock_api_client.config = MagicMock()
        mock_api_client.config.base_url = "https://example.com"
        mock_api_client.config.api_key = "test-key"
        mock_api_client.list_emails = AsyncMock(return_value=[])

        strategy = SSEStrategy(mock_api_client)

        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"

        callback_called = False

        def callback(email):
            nonlocal callback_called
            callback_called = True

        # Manually add subscription
        subscription = Subscription(inbox=mock_inbox, callback=callback)
        strategy._subscriptions["test@example.com"] = subscription
        strategy._inbox_hash_map["test-hash"] = "test@example.com"

        # Unsubscribe
        await strategy.unsubscribe(subscription)

        # Simulate an event arriving after unsubscribe
        # _handle_event should skip this since subscription is gone
        await strategy._handle_event('{"inboxId": "test-hash", "emailId": "email-1"}')

        # Callback should not have been called
        assert not callback_called

        await strategy.close()

    @pytest.mark.asyncio
    async def test_seen_emails_preserved_during_resubscribe(self) -> None:
        """Test that seen emails are tracked per-subscription."""
        mock_api_client = MagicMock()
        mock_api_client.config = MagicMock()
        mock_api_client.config.base_url = "https://example.com"
        mock_api_client.config.api_key = "test-key"
        mock_api_client.list_emails = AsyncMock(return_value=[])

        strategy = SSEStrategy(mock_api_client)

        async def mock_reconnect():
            strategy._connected_event = asyncio.Event()
            strategy._connected_event.set()

        strategy._reconnect_sse = mock_reconnect

        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"

        callback_count = 0

        def callback(email):
            nonlocal callback_count
            callback_count += 1

        # First subscription
        subscription1 = await strategy.subscribe(mock_inbox, callback)
        subscription1.mark_seen("email-1")

        # Unsubscribe
        await strategy.unsubscribe(subscription1)

        # Resubscribe (creates new subscription)
        subscription2 = await strategy.subscribe(mock_inbox, callback)

        # New subscription should not have seen the email
        assert not subscription2.has_seen("email-1")

        await strategy.close()


class TestConcurrentCleanup:
    """Tests for concurrent cleanup operations."""

    @pytest.mark.asyncio
    async def test_close_during_subscribe(self) -> None:
        """Test closing strategy while subscribe is in progress."""
        mock_api_client = MagicMock()
        mock_api_client.config = MagicMock()
        mock_api_client.config.base_url = "https://example.com"
        mock_api_client.config.api_key = "test-key"
        mock_api_client.list_emails = AsyncMock(return_value=[])

        strategy = SSEStrategy(mock_api_client)

        # Slow reconnect
        async def mock_reconnect():
            await asyncio.sleep(0.1)  # Long reconnection
            if strategy._running:
                strategy._connected_event = asyncio.Event()
                strategy._connected_event.set()

        strategy._reconnect_sse = mock_reconnect

        mock_inbox = MagicMock()
        mock_inbox.email_address = "test@example.com"
        mock_inbox.inbox_hash = "test-hash"

        # Start subscribe in background, then close immediately
        async def subscribe_task():
            with contextlib.suppress(Exception):
                await strategy.subscribe(mock_inbox, lambda e: None)

        subscribe_coro = subscribe_task()

        # Schedule subscribe and close concurrently
        await asyncio.gather(
            subscribe_coro,
            strategy.close(),
            return_exceptions=True,
        )

        # After close, strategy should be cleaned up
        assert strategy._running is False

    @pytest.mark.asyncio
    async def test_multiple_close_calls(self) -> None:
        """Test calling close multiple times is safe."""
        mock_api_client = MagicMock()
        strategy = SSEStrategy(mock_api_client)

        # Close multiple times concurrently
        await asyncio.gather(
            strategy.close(),
            strategy.close(),
            strategy.close(),
        )

        # Should not raise, strategy should be cleanly closed
        assert strategy._running is False
        assert len(strategy._subscriptions) == 0


class TestLockContention:
    """Tests for lock contention scenarios."""

    @pytest.mark.asyncio
    async def test_high_contention_subscribe_unsubscribe(self) -> None:
        """Test high contention with many concurrent operations."""
        mock_api_client = MagicMock()
        mock_api_client.config = MagicMock()
        mock_api_client.config.base_url = "https://example.com"
        mock_api_client.config.api_key = "test-key"
        mock_api_client.list_emails = AsyncMock(return_value=[])

        strategy = SSEStrategy(mock_api_client)

        async def mock_reconnect():
            strategy._connected_event = asyncio.Event()
            strategy._connected_event.set()

        strategy._reconnect_sse = mock_reconnect

        # Create many inboxes
        inboxes = []
        for i in range(20):
            mock_inbox = MagicMock()
            mock_inbox.email_address = f"test{i}@example.com"
            mock_inbox.inbox_hash = f"test-hash-{i}"
            inboxes.append(mock_inbox)

        # Subscribe and unsubscribe in rapid succession
        subscriptions = await asyncio.gather(
            *[strategy.subscribe(inbox, lambda e: None) for inbox in inboxes]
        )

        # Unsubscribe all
        await asyncio.gather(*[strategy.unsubscribe(sub) for sub in subscriptions])

        # Everything should be cleaned up
        assert len(strategy._subscriptions) == 0
        assert len(strategy._inbox_hash_map) == 0

        await strategy.close()
