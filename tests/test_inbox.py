"""Tests for Inbox class."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from vaultsandbox.crypto import generate_keypair, to_base64
from vaultsandbox.inbox import Inbox
from vaultsandbox.types import ExportedInbox


class TestInboxExport:
    """Tests for Inbox.export() method."""

    def test_export_returns_exported_inbox(self) -> None:
        """Test export returns ExportedInbox with correct data."""
        keypair = generate_keypair()
        expires_at = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        inbox = Inbox(
            email_address="test@example.com",
            expires_at=expires_at,
            inbox_hash="test-hash",
            server_sig_pk="test-server-pk",
            _keypair=keypair,
            _api_client=MagicMock(),
            _strategy=MagicMock(),
        )

        exported = inbox.export()

        assert isinstance(exported, ExportedInbox)
        assert exported.email_address == "test@example.com"
        assert exported.expires_at == "2025-01-01T12:00:00Z"
        assert exported.inbox_hash == "test-hash"
        assert exported.server_sig_pk == "test-server-pk"
        assert exported.public_key_b64 == to_base64(keypair.public_key)
        assert exported.secret_key_b64 == to_base64(keypair.secret_key)
        assert exported.exported_at is not None

    def test_export_contains_valid_keys(self) -> None:
        """Test exported data contains valid base64-encoded keys."""
        keypair = generate_keypair()
        expires_at = datetime(2025, 1, 1, tzinfo=timezone.utc)

        inbox = Inbox(
            email_address="test@example.com",
            expires_at=expires_at,
            inbox_hash="test-hash",
            server_sig_pk="test-server-pk",
            _keypair=keypair,
            _api_client=MagicMock(),
            _strategy=MagicMock(),
        )

        exported = inbox.export()

        # Keys should be non-empty base64 strings
        assert len(exported.public_key_b64) > 0
        assert len(exported.secret_key_b64) > 0

        # Should be valid base64 (can include padding)
        import base64

        # Verify keys can be decoded
        base64.b64decode(exported.public_key_b64)
        base64.b64decode(exported.secret_key_b64)


class TestInboxDelete:
    """Tests for Inbox.delete() method."""

    @pytest.mark.asyncio
    async def test_delete_unsubscribes_and_deletes(self) -> None:
        """Test delete unsubscribes from all subscriptions and deletes inbox."""
        keypair = generate_keypair()
        mock_api_client = MagicMock()
        mock_api_client.delete_inbox = AsyncMock()
        mock_strategy = MagicMock()
        mock_strategy.unsubscribe = AsyncMock()

        inbox = Inbox(
            email_address="test@example.com",
            expires_at=datetime.now(timezone.utc),
            inbox_hash="test-hash",
            server_sig_pk="test-server-pk",
            _keypair=keypair,
            _api_client=mock_api_client,
            _strategy=mock_strategy,
        )

        # Add some subscriptions
        sub1 = MagicMock()
        sub2 = MagicMock()
        inbox._subscriptions = [sub1, sub2]

        await inbox.delete()

        # Should unsubscribe from all subscriptions
        assert mock_strategy.unsubscribe.call_count == 2
        mock_strategy.unsubscribe.assert_any_call(sub1)
        mock_strategy.unsubscribe.assert_any_call(sub2)

        # Should clear subscriptions list
        assert len(inbox._subscriptions) == 0

        # Should delete inbox via API
        mock_api_client.delete_inbox.assert_called_once_with("test@example.com")


class TestInboxGetSyncStatus:
    """Tests for Inbox.get_sync_status() method."""

    @pytest.mark.asyncio
    async def test_get_sync_status_calls_api(self) -> None:
        """Test get_sync_status calls API client correctly."""
        keypair = generate_keypair()
        mock_api_client = MagicMock()
        mock_sync_status = MagicMock()
        mock_api_client.get_sync_status = AsyncMock(return_value=mock_sync_status)

        inbox = Inbox(
            email_address="test@example.com",
            expires_at=datetime.now(timezone.utc),
            inbox_hash="test-hash",
            server_sig_pk="test-server-pk",
            _keypair=keypair,
            _api_client=mock_api_client,
            _strategy=MagicMock(),
        )

        result = await inbox.get_sync_status()

        assert result == mock_sync_status
        mock_api_client.get_sync_status.assert_called_once_with("test@example.com")


class TestInboxMarkEmailAsRead:
    """Tests for Inbox.mark_email_as_read() method."""

    @pytest.mark.asyncio
    async def test_mark_email_as_read_calls_api(self) -> None:
        """Test mark_email_as_read calls API client correctly."""
        keypair = generate_keypair()
        mock_api_client = MagicMock()
        mock_api_client.mark_email_as_read = AsyncMock()

        inbox = Inbox(
            email_address="test@example.com",
            expires_at=datetime.now(timezone.utc),
            inbox_hash="test-hash",
            server_sig_pk="test-server-pk",
            _keypair=keypair,
            _api_client=mock_api_client,
            _strategy=MagicMock(),
        )

        await inbox.mark_email_as_read("email-123")

        mock_api_client.mark_email_as_read.assert_called_once_with("test@example.com", "email-123")


class TestInboxDeleteEmail:
    """Tests for Inbox.delete_email() method."""

    @pytest.mark.asyncio
    async def test_delete_email_calls_api(self) -> None:
        """Test delete_email calls API client correctly."""
        keypair = generate_keypair()
        mock_api_client = MagicMock()
        mock_api_client.delete_email = AsyncMock()

        inbox = Inbox(
            email_address="test@example.com",
            expires_at=datetime.now(timezone.utc),
            inbox_hash="test-hash",
            server_sig_pk="test-server-pk",
            _keypair=keypair,
            _api_client=mock_api_client,
            _strategy=MagicMock(),
        )

        await inbox.delete_email("email-456")

        mock_api_client.delete_email.assert_called_once_with("test@example.com", "email-456")


class TestInboxOnNewEmail:
    """Tests for Inbox.on_new_email() method."""

    @pytest.mark.asyncio
    async def test_on_new_email_subscribes_with_strategy(self) -> None:
        """Test on_new_email subscribes using the strategy."""
        keypair = generate_keypair()
        mock_api_client = MagicMock()
        mock_api_client.list_emails = AsyncMock(return_value=[])
        mock_strategy = MagicMock()
        mock_subscription = MagicMock()
        mock_strategy.subscribe = AsyncMock(return_value=mock_subscription)

        inbox = Inbox(
            email_address="test@example.com",
            expires_at=datetime.now(timezone.utc),
            inbox_hash="test-hash",
            server_sig_pk="test-server-pk",
            _keypair=keypair,
            _api_client=mock_api_client,
            _strategy=mock_strategy,
        )

        callback = MagicMock()
        result = await inbox.on_new_email(callback)

        assert result == mock_subscription
        mock_strategy.subscribe.assert_called_once()
        assert mock_subscription in inbox._subscriptions

    @pytest.mark.asyncio
    async def test_on_new_email_marks_existing_seen_by_default(self) -> None:
        """Test on_new_email marks existing emails as seen by default."""
        keypair = generate_keypair()
        mock_api_client = MagicMock()

        mock_strategy = MagicMock()
        mock_subscription = MagicMock()
        mock_strategy.subscribe = AsyncMock(return_value=mock_subscription)

        inbox = Inbox(
            email_address="test@example.com",
            expires_at=datetime.now(timezone.utc),
            inbox_hash="test-hash",
            server_sig_pk="test-server-pk",
            _keypair=keypair,
            _api_client=mock_api_client,
            _strategy=mock_strategy,
        )

        # Mock list_emails on the inbox instance to return mock emails
        mock_email1 = MagicMock()
        mock_email1.id = "email-1"
        mock_email2 = MagicMock()
        mock_email2.id = "email-2"
        inbox.list_emails = AsyncMock(return_value=[mock_email1, mock_email2])

        callback = MagicMock()
        await inbox.on_new_email(callback)

        # Should mark existing emails as seen
        assert mock_subscription.mark_seen.call_count == 2
        mock_subscription.mark_seen.assert_any_call("email-1")
        mock_subscription.mark_seen.assert_any_call("email-2")

    @pytest.mark.asyncio
    async def test_on_new_email_skip_marking_seen(self) -> None:
        """Test on_new_email can skip marking existing emails as seen."""
        keypair = generate_keypair()
        mock_api_client = MagicMock()
        mock_api_client.list_emails = AsyncMock(return_value=[{"id": "email-1"}])

        mock_strategy = MagicMock()
        mock_subscription = MagicMock()
        mock_strategy.subscribe = AsyncMock(return_value=mock_subscription)

        inbox = Inbox(
            email_address="test@example.com",
            expires_at=datetime.now(timezone.utc),
            inbox_hash="test-hash",
            server_sig_pk="test-server-pk",
            _keypair=keypair,
            _api_client=mock_api_client,
            _strategy=mock_strategy,
        )

        callback = MagicMock()
        await inbox.on_new_email(callback, mark_existing_seen=False)

        # Should NOT mark existing emails as seen
        mock_subscription.mark_seen.assert_not_called()
        # Should NOT call list_emails when mark_existing_seen=False
        mock_api_client.list_emails.assert_not_called()


class TestInboxWaitForEmailCount:
    """Tests for Inbox.wait_for_email_count() method."""

    @pytest.mark.asyncio
    async def test_wait_for_email_count_uses_strategy(self) -> None:
        """Verify wait_for_email_count uses the delivery strategy, not hardcoded polling."""
        keypair = generate_keypair()
        mock_api_client = MagicMock()
        mock_strategy = MagicMock()
        mock_subscription = MagicMock()
        mock_strategy.subscribe = AsyncMock(return_value=mock_subscription)
        mock_strategy.unsubscribe = AsyncMock()

        inbox = Inbox(
            email_address="test@example.com",
            expires_at=datetime.now(timezone.utc),
            inbox_hash="test-hash",
            server_sig_pk="test-server-pk",
            _keypair=keypair,
            _api_client=mock_api_client,
            _strategy=mock_strategy,
        )

        # Mock list_emails to return 2 emails
        mock_email1 = MagicMock()
        mock_email1.id = "email-1"
        mock_email2 = MagicMock()
        mock_email2.id = "email-2"
        inbox.list_emails = AsyncMock(return_value=[mock_email1, mock_email2])

        # Wait for 2 emails
        from vaultsandbox.types import WaitForCountOptions

        emails = await inbox.wait_for_email_count(2, WaitForCountOptions(timeout=10000))

        assert len(emails) >= 2
        # Verify strategy was used (subscribe was called)
        mock_strategy.subscribe.assert_called_once()
        # Verify cleanup happened
        mock_strategy.unsubscribe.assert_called_once_with(mock_subscription)

    @pytest.mark.asyncio
    async def test_wait_for_email_count_timeout(self) -> None:
        """Test wait_for_email_count raises TimeoutError when count not reached."""
        keypair = generate_keypair()
        mock_api_client = MagicMock()
        mock_strategy = MagicMock()
        mock_subscription = MagicMock()
        mock_strategy.subscribe = AsyncMock(return_value=mock_subscription)
        mock_strategy.unsubscribe = AsyncMock()

        inbox = Inbox(
            email_address="test@example.com",
            expires_at=datetime.now(timezone.utc),
            inbox_hash="test-hash",
            server_sig_pk="test-server-pk",
            _keypair=keypair,
            _api_client=mock_api_client,
            _strategy=mock_strategy,
        )

        # Mock list_emails to return only 1 email
        mock_email = MagicMock()
        mock_email.id = "email-1"
        inbox.list_emails = AsyncMock(return_value=[mock_email])

        from vaultsandbox.errors import TimeoutError
        from vaultsandbox.types import WaitForCountOptions

        with pytest.raises(TimeoutError, match="Timeout waiting for 3 emails"):
            await inbox.wait_for_email_count(3, WaitForCountOptions(timeout=100))

        # Verify cleanup still happened
        mock_strategy.unsubscribe.assert_called_once_with(mock_subscription)
