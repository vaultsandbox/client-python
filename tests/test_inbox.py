"""Tests for Inbox class."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vaultsandbox.crypto import generate_keypair, to_base64url
from vaultsandbox.inbox import Inbox
from vaultsandbox.types import EmailMetadata, ExportedInbox


class TestInboxExport:
    """Tests for Inbox.export() method."""

    def test_export_returns_exported_inbox(self) -> None:
        """Test export returns ExportedInbox with correct data per Section 9."""
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
        assert exported.version == 1  # Per Section 9.3
        assert exported.email_address == "test@example.com"
        assert exported.expires_at == "2025-01-01T12:00:00Z"
        assert exported.inbox_hash == "test-hash"
        assert exported.encrypted is True
        assert exported.server_sig_pk == "test-server-pk"
        assert exported.secret_key == to_base64url(keypair.secret_key)
        assert exported.exported_at is not None

    def test_export_contains_valid_keys(self) -> None:
        """Test exported data contains valid base64url-encoded secret key."""
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

        # Secret key should be non-empty base64url string
        assert len(exported.secret_key) > 0

        # Should be valid base64url (no padding per Section 2.2)
        from vaultsandbox.crypto import from_base64url

        # Verify key can be decoded
        decoded = from_base64url(exported.secret_key)
        assert len(decoded) == 2400  # MLKEM768_SECRET_KEY_SIZE


class TestInboxListEmailsMetadataOnly:
    """Tests for Inbox.list_emails_metadata_only() method."""

    @pytest.mark.asyncio
    async def test_list_emails_metadata_only_returns_metadata(self) -> None:
        """Test list_emails_metadata_only returns EmailMetadata objects."""
        keypair = generate_keypair()
        mock_api_client = MagicMock()
        mock_api_client.list_emails = AsyncMock(
            return_value=[
                {
                    "id": "email-1",
                    "encryptedMetadata": {"mock": "encrypted"},
                    "isRead": True,
                },
                {
                    "id": "email-2",
                    "encryptedMetadata": {"mock": "encrypted2"},
                    "isRead": False,
                },
            ]
        )

        inbox = Inbox(
            email_address="test@example.com",
            expires_at=datetime.now(timezone.utc),
            inbox_hash="test-hash",
            server_sig_pk="test-server-pk",
            _keypair=keypair,
            _api_client=mock_api_client,
            _strategy=MagicMock(),
        )

        # Mock decrypt_metadata to return test data
        with patch("vaultsandbox.inbox.decrypt_metadata") as mock_decrypt:
            mock_decrypt.side_effect = [
                {
                    "from": "sender1@example.com",
                    "subject": "Test Subject 1",
                    "receivedAt": "2025-01-01T12:00:00Z",
                },
                {
                    "from": "sender2@example.com",
                    "subject": "Test Subject 2",
                    "receivedAt": "2025-01-02T13:00:00Z",
                },
            ]

            result = await inbox.list_emails_metadata_only()

        # Verify API was called correctly
        mock_api_client.list_emails.assert_called_once_with(
            "test@example.com", include_content=False
        )

        # Verify decrypt_metadata was called for each email
        assert mock_decrypt.call_count == 2
        mock_decrypt.assert_any_call(
            {"mock": "encrypted"},
            keypair,
            pinned_server_key="test-server-pk",
        )

        # Verify result is correct
        assert len(result) == 2
        assert isinstance(result[0], EmailMetadata)
        assert result[0].id == "email-1"
        assert result[0].from_address == "sender1@example.com"
        assert result[0].subject == "Test Subject 1"
        assert result[0].is_read is True

        assert result[1].id == "email-2"
        assert result[1].from_address == "sender2@example.com"
        assert result[1].subject == "Test Subject 2"
        assert result[1].is_read is False

    @pytest.mark.asyncio
    async def test_list_emails_metadata_only_empty_inbox(self) -> None:
        """Test list_emails_metadata_only with empty inbox."""
        keypair = generate_keypair()
        mock_api_client = MagicMock()
        mock_api_client.list_emails = AsyncMock(return_value=[])

        inbox = Inbox(
            email_address="test@example.com",
            expires_at=datetime.now(timezone.utc),
            inbox_hash="test-hash",
            server_sig_pk="test-server-pk",
            _keypair=keypair,
            _api_client=mock_api_client,
            _strategy=MagicMock(),
        )

        result = await inbox.list_emails_metadata_only()

        assert result == []
        mock_api_client.list_emails.assert_called_once_with(
            "test@example.com", include_content=False
        )

    @pytest.mark.asyncio
    async def test_list_emails_metadata_only_plain_inbox(self) -> None:
        """Test list_emails_metadata_only with plain (unencrypted) inbox."""
        import base64
        import json

        mock_api_client = MagicMock()
        # Plain email response has 'metadata' field (base64 encoded) instead of 'encryptedMetadata'
        metadata = {
            "from": "sender@example.com",
            "subject": "Plain Email",
            "receivedAt": "2025-01-01T12:00:00Z",
        }
        mock_api_client.list_emails = AsyncMock(
            return_value=[
                {
                    "id": "email-plain",
                    "metadata": base64.b64encode(json.dumps(metadata).encode()).decode(),
                    "isRead": False,
                },
            ]
        )

        # Plain inbox has no keypair
        inbox = Inbox(
            email_address="plain@example.com",
            expires_at=datetime.now(timezone.utc),
            inbox_hash="test-hash",
            _api_client=mock_api_client,
            _strategy=MagicMock(),
            encrypted=False,
            server_sig_pk=None,
            _keypair=None,
        )

        result = await inbox.list_emails_metadata_only()

        assert len(result) == 1
        assert result[0].id == "email-plain"
        assert result[0].from_address == "sender@example.com"
        assert result[0].subject == "Plain Email"
        assert result[0].is_read is False


class TestInboxGetEmail:
    """Tests for Inbox.get_email() method."""

    @pytest.mark.asyncio
    async def test_get_email_calls_api(self) -> None:
        """Test get_email retrieves email via API client."""
        keypair = generate_keypair()
        mock_api_client = MagicMock()
        mock_response = {"id": "email-123", "content": "test"}
        mock_api_client.get_email = AsyncMock(return_value=mock_response)

        inbox = Inbox(
            email_address="test@example.com",
            expires_at=datetime.now(timezone.utc),
            inbox_hash="test-hash",
            server_sig_pk="test-server-pk",
            _keypair=keypair,
            _api_client=mock_api_client,
            _strategy=MagicMock(),
        )

        # Mock Email._from_response
        with patch("vaultsandbox.inbox.Email._from_response") as mock_from_response:
            mock_email = MagicMock()
            mock_email.id = "email-123"
            mock_from_response.return_value = mock_email

            result = await inbox.get_email("email-123")

        assert result.id == "email-123"
        mock_api_client.get_email.assert_called_once_with("test@example.com", "email-123")
        mock_from_response.assert_called_once_with(mock_response, inbox)


class TestInboxGetRawEmail:
    """Tests for Inbox.get_raw_email() method."""

    @pytest.mark.asyncio
    async def test_get_raw_email_decrypts_and_returns(self) -> None:
        """Test get_raw_email retrieves and decrypts raw MIME content."""
        keypair = generate_keypair()
        mock_api_client = MagicMock()
        mock_api_client.get_raw_email = AsyncMock(
            return_value={
                "id": "email-123",
                "encryptedRaw": {"mock": "encrypted"},
            }
        )

        inbox = Inbox(
            email_address="test@example.com",
            expires_at=datetime.now(timezone.utc),
            inbox_hash="test-hash",
            server_sig_pk="test-server-pk",
            _keypair=keypair,
            _api_client=mock_api_client,
            _strategy=MagicMock(),
        )

        with patch("vaultsandbox.crypto.decrypt_raw") as mock_decrypt_raw:
            mock_decrypt_raw.return_value = b"From: test@example.com\r\nSubject: Test\r\n\r\nBody"

            result = await inbox.get_raw_email("email-123")

            assert result.id == "email-123"
            assert result.raw == b"From: test@example.com\r\nSubject: Test\r\n\r\nBody"
            mock_api_client.get_raw_email.assert_called_once_with("test@example.com", "email-123")
            mock_decrypt_raw.assert_called_once_with(
                {"mock": "encrypted"},
                keypair,
                pinned_server_key="test-server-pk",
            )

    @pytest.mark.asyncio
    async def test_get_raw_email_plain_inbox(self) -> None:
        """Test get_raw_email with plain (unencrypted) inbox."""
        import base64

        mock_api_client = MagicMock()
        raw_content = "From: sender@example.com\r\nSubject: Plain\r\n\r\nBody"
        mock_api_client.get_raw_email = AsyncMock(
            return_value={
                "id": "email-plain",
                "raw": base64.b64encode(raw_content.encode()).decode(),
            }
        )

        # Plain inbox has no keypair
        inbox = Inbox(
            email_address="plain@example.com",
            expires_at=datetime.now(timezone.utc),
            inbox_hash="test-hash",
            _api_client=mock_api_client,
            _strategy=MagicMock(),
            encrypted=False,
            server_sig_pk=None,
            _keypair=None,
        )

        result = await inbox.get_raw_email("email-plain")

        assert result.id == "email-plain"
        assert result.raw == raw_content
        mock_api_client.get_raw_email.assert_called_once_with("plain@example.com", "email-plain")


class TestInboxUnsubscribe:
    """Tests for Inbox.unsubscribe() method."""

    @pytest.mark.asyncio
    async def test_unsubscribe_removes_subscription(self) -> None:
        """Test unsubscribe removes subscription from list."""
        keypair = generate_keypair()
        mock_api_client = MagicMock()
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

        # Add a subscription to the list
        mock_subscription = MagicMock()
        inbox._subscriptions = [mock_subscription]

        await inbox.unsubscribe(mock_subscription)

        # Verify strategy.unsubscribe was called
        mock_strategy.unsubscribe.assert_called_once_with(mock_subscription)
        # Verify subscription was removed from the list
        assert mock_subscription not in inbox._subscriptions

    @pytest.mark.asyncio
    async def test_unsubscribe_handles_missing_subscription(self) -> None:
        """Test unsubscribe handles subscription not in list."""
        keypair = generate_keypair()
        mock_api_client = MagicMock()
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

        # Subscription not in list
        mock_subscription = MagicMock()
        inbox._subscriptions = []

        # Should not raise
        await inbox.unsubscribe(mock_subscription)

        mock_strategy.unsubscribe.assert_called_once_with(mock_subscription)


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

    @pytest.mark.asyncio
    async def test_wait_for_email_count_callback_after_done(self) -> None:
        """Test wait_for_email_count callback early return when result already set (lines 230, 236)."""
        import asyncio

        keypair = generate_keypair()
        mock_api_client = MagicMock()
        mock_strategy = MagicMock()
        mock_subscription = MagicMock()
        captured_callback = None

        async def capture_subscribe(inbox, callback):
            nonlocal captured_callback
            captured_callback = callback
            return mock_subscription

        mock_strategy.subscribe = AsyncMock(side_effect=capture_subscribe)
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

        # Mock list_emails to return 2 emails immediately (meeting the count)
        mock_email1 = MagicMock()
        mock_email1.id = "email-1"
        mock_email2 = MagicMock()
        mock_email2.id = "email-2"
        inbox.list_emails = AsyncMock(return_value=[mock_email1, mock_email2])

        from vaultsandbox.types import WaitForCountOptions

        # Start wait_for_email_count in a task
        task = asyncio.create_task(
            inbox.wait_for_email_count(2, WaitForCountOptions(timeout=10000))
        )

        # Let the task run to completion
        emails = await task

        assert len(emails) == 2

        # Now the result_future is done. Call the callback again to test early return (line 230)
        # This should trigger the early return path when result_future.done() is True
        if captured_callback:
            mock_new_email = MagicMock()
            mock_new_email.id = "email-3"
            # This callback call exercises line 236, and the check_count early return at line 230
            await captured_callback(mock_new_email)


class TestInboxWaitForEmail:
    """Tests for Inbox.wait_for_email() method."""

    @pytest.mark.asyncio
    async def test_wait_for_email_callback_after_done(self) -> None:
        """Test wait_for_email callback early return when result already set (lines 178-181)."""

        keypair = generate_keypair()
        mock_api_client = MagicMock()
        mock_strategy = MagicMock()
        mock_subscription = MagicMock()
        captured_callback = None

        async def capture_subscribe(inbox, callback):
            nonlocal captured_callback
            captured_callback = callback
            return mock_subscription

        mock_strategy.subscribe = AsyncMock(side_effect=capture_subscribe)
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

        # Mock list_emails to return one matching email immediately
        mock_email = MagicMock()
        mock_email.id = "email-1"
        mock_email.subject = "Test Subject"
        mock_email.from_address = "sender@example.com"
        inbox.list_emails = AsyncMock(return_value=[mock_email])

        from vaultsandbox.types import WaitForEmailOptions

        # Wait for email - should find the existing one
        result = await inbox.wait_for_email(WaitForEmailOptions(timeout=10000))

        assert result.id == "email-1"

        # Now the result_future is done. Call the callback again to test early return (line 178-179)
        if captured_callback:
            mock_new_email = MagicMock()
            mock_new_email.id = "email-2"
            mock_new_email.subject = "Another Subject"
            mock_new_email.from_address = "another@example.com"
            # This callback call should hit the early return at lines 178-179
            await captured_callback(mock_new_email)

    @pytest.mark.asyncio
    async def test_wait_for_email_callback_sets_result(self) -> None:
        """Test wait_for_email callback sets result when filter matches (lines 180-181)."""
        import asyncio

        keypair = generate_keypair()
        mock_api_client = MagicMock()
        mock_strategy = MagicMock()
        mock_subscription = MagicMock()
        captured_callback = None

        async def capture_subscribe(inbox, callback):
            nonlocal captured_callback
            captured_callback = callback
            return mock_subscription

        mock_strategy.subscribe = AsyncMock(side_effect=capture_subscribe)
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

        # Mock list_emails to return empty list initially
        inbox.list_emails = AsyncMock(return_value=[])

        from vaultsandbox.types import WaitForEmailOptions

        # Start wait_for_email with a short timeout
        task = asyncio.create_task(inbox.wait_for_email(WaitForEmailOptions(timeout=5000)))

        # Give the task a moment to set up
        await asyncio.sleep(0.01)

        # Simulate a new email arriving that matches the filter
        # This exercises lines 180-181 (matches_filter check and set_result)
        if captured_callback:
            mock_new_email = MagicMock()
            mock_new_email.id = "email-new"
            mock_new_email.subject = "New Email"
            mock_new_email.from_address = "sender@example.com"
            await captured_callback(mock_new_email)

        result = await task
        assert result.id == "email-new"

    @pytest.mark.asyncio
    async def test_wait_for_email_timeout(self) -> None:
        """Test wait_for_email raises TimeoutError when no match found."""
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

        # Mock list_emails to return empty list
        inbox.list_emails = AsyncMock(return_value=[])

        from vaultsandbox.errors import TimeoutError
        from vaultsandbox.types import WaitForEmailOptions

        with pytest.raises(TimeoutError, match="Timeout waiting for email"):
            await inbox.wait_for_email(WaitForEmailOptions(timeout=100))
