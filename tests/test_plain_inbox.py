"""Tests for plain (non-encrypted) inbox operations."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from vaultsandbox.errors import InvalidPayloadError
from vaultsandbox.inbox import Inbox
from vaultsandbox.types import EmailMetadata


class TestPlainInboxListEmailsMetadataOnly:
    """Tests for listing emails with metadata only for plain inboxes."""

    @pytest.mark.asyncio
    async def test_list_emails_metadata_only_plain_inbox(self) -> None:
        """Test list_emails_metadata_only works for plain (non-encrypted) emails."""
        # Create metadata as base64-encoded JSON (how plain emails are stored)
        metadata1 = {
            "from": "sender1@example.com",
            "subject": "Test Subject 1",
            "receivedAt": "2025-01-01T12:00:00Z",
        }
        metadata2 = {
            "from": "sender2@example.com",
            "subject": "Test Subject 2",
            "receivedAt": "2025-01-02T13:00:00Z",
        }
        metadata1_b64 = base64.b64encode(json.dumps(metadata1).encode()).decode()
        metadata2_b64 = base64.b64encode(json.dumps(metadata2).encode()).decode()

        mock_api_client = MagicMock()
        mock_api_client.list_emails = AsyncMock(
            return_value=[
                {
                    "id": "email-1",
                    "metadata": metadata1_b64,
                    "isRead": True,
                },
                {
                    "id": "email-2",
                    "metadata": metadata2_b64,
                    "isRead": False,
                },
            ]
        )

        # Plain inbox - no keypair
        inbox = Inbox(
            email_address="plain@example.com",
            expires_at=datetime.now(timezone.utc),
            inbox_hash="plain-hash",
            encrypted=False,
            _keypair=None,
            _api_client=mock_api_client,
            _strategy=MagicMock(),
        )

        result = await inbox.list_emails_metadata_only()

        # Verify API was called correctly
        mock_api_client.list_emails.assert_called_once_with(
            "plain@example.com", include_content=False
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
    async def test_list_emails_metadata_only_invalid_base64(self) -> None:
        """Test list_emails_metadata_only raises InvalidPayloadError on invalid base64."""
        mock_api_client = MagicMock()
        mock_api_client.list_emails = AsyncMock(
            return_value=[
                {
                    "id": "email-1",
                    "metadata": "not-valid-base64!!!",
                    "isRead": False,
                },
            ]
        )

        inbox = Inbox(
            email_address="plain@example.com",
            expires_at=datetime.now(timezone.utc),
            inbox_hash="plain-hash",
            encrypted=False,
            _keypair=None,
            _api_client=mock_api_client,
            _strategy=MagicMock(),
        )

        with pytest.raises(InvalidPayloadError) as exc_info:
            await inbox.list_emails_metadata_only()

        assert "Failed to decode email metadata" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_list_emails_metadata_only_invalid_json(self) -> None:
        """Test list_emails_metadata_only raises InvalidPayloadError on invalid JSON."""
        # Valid base64, but not valid JSON
        invalid_json_b64 = base64.b64encode(b"not json").decode()

        mock_api_client = MagicMock()
        mock_api_client.list_emails = AsyncMock(
            return_value=[
                {
                    "id": "email-1",
                    "metadata": invalid_json_b64,
                    "isRead": False,
                },
            ]
        )

        inbox = Inbox(
            email_address="plain@example.com",
            expires_at=datetime.now(timezone.utc),
            inbox_hash="plain-hash",
            encrypted=False,
            _keypair=None,
            _api_client=mock_api_client,
            _strategy=MagicMock(),
        )

        with pytest.raises(InvalidPayloadError) as exc_info:
            await inbox.list_emails_metadata_only()

        assert "Failed to decode email metadata" in str(exc_info.value)


class TestPlainInboxGetRawEmail:
    """Tests for get_raw_email for plain inboxes."""

    @pytest.mark.asyncio
    async def test_get_raw_email_plain_inbox(self) -> None:
        """Test get_raw_email works for plain (non-encrypted) emails."""
        raw_content = "From: test@example.com\r\nSubject: Test\r\n\r\nBody"
        raw_b64 = base64.b64encode(raw_content.encode()).decode()

        mock_api_client = MagicMock()
        mock_api_client.get_raw_email = AsyncMock(
            return_value={
                "id": "email-1",
                "raw": raw_b64,
            }
        )

        inbox = Inbox(
            email_address="plain@example.com",
            expires_at=datetime.now(timezone.utc),
            inbox_hash="plain-hash",
            encrypted=False,
            _keypair=None,
            _api_client=mock_api_client,
            _strategy=MagicMock(),
        )

        result = await inbox.get_raw_email("email-1")

        mock_api_client.get_raw_email.assert_called_once_with("plain@example.com", "email-1")
        assert result.id == "email-1"
        assert result.raw == raw_content

    @pytest.mark.asyncio
    async def test_get_raw_email_invalid_base64(self) -> None:
        """Test get_raw_email raises InvalidPayloadError on invalid base64."""
        mock_api_client = MagicMock()
        mock_api_client.get_raw_email = AsyncMock(
            return_value={
                "id": "email-1",
                "raw": "not-valid-base64!!!",
            }
        )

        inbox = Inbox(
            email_address="plain@example.com",
            expires_at=datetime.now(timezone.utc),
            inbox_hash="plain-hash",
            encrypted=False,
            _keypair=None,
            _api_client=mock_api_client,
            _strategy=MagicMock(),
        )

        with pytest.raises(InvalidPayloadError) as exc_info:
            await inbox.get_raw_email("email-1")

        assert "Failed to decode raw email" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_get_raw_email_invalid_utf8(self) -> None:
        """Test get_raw_email raises InvalidPayloadError on invalid UTF-8."""
        # Create base64 content that decodes to invalid UTF-8
        invalid_utf8 = base64.b64encode(b"\xff\xfe").decode()

        mock_api_client = MagicMock()
        mock_api_client.get_raw_email = AsyncMock(
            return_value={
                "id": "email-1",
                "raw": invalid_utf8,
            }
        )

        inbox = Inbox(
            email_address="plain@example.com",
            expires_at=datetime.now(timezone.utc),
            inbox_hash="plain-hash",
            encrypted=False,
            _keypair=None,
            _api_client=mock_api_client,
            _strategy=MagicMock(),
        )

        with pytest.raises(InvalidPayloadError) as exc_info:
            await inbox.get_raw_email("email-1")

        assert "Failed to decode raw email" in str(exc_info.value)


class TestPlainInboxNoKeypair:
    """Tests verifying plain inbox operations work without a keypair."""

    @pytest.mark.asyncio
    async def test_plain_inbox_operations_without_keypair(self) -> None:
        """Test that plain inbox operations work without a keypair."""
        metadata = {
            "from": "sender@example.com",
            "subject": "Test Subject",
            "receivedAt": "2025-01-01T12:00:00Z",
        }
        metadata_b64 = base64.b64encode(json.dumps(metadata).encode()).decode()

        mock_api_client = MagicMock()
        mock_api_client.list_emails = AsyncMock(
            return_value=[
                {
                    "id": "email-1",
                    "metadata": metadata_b64,
                    "isRead": False,
                },
            ]
        )

        # Plain inbox explicitly without a keypair
        inbox = Inbox(
            email_address="plain@example.com",
            expires_at=datetime.now(timezone.utc),
            inbox_hash="plain-hash",
            encrypted=False,
            _keypair=None,  # No keypair
            _api_client=mock_api_client,
            _strategy=MagicMock(),
        )

        # Verify keypair is None
        assert inbox._keypair is None

        # This should work without raising any errors
        result = await inbox.list_emails_metadata_only()
        assert len(result) == 1
        assert result[0].from_address == "sender@example.com"

    @pytest.mark.asyncio
    async def test_plain_inbox_delete_email(self) -> None:
        """Test that plain inbox can delete emails."""
        mock_api_client = MagicMock()
        mock_api_client.delete_email = AsyncMock()

        inbox = Inbox(
            email_address="plain@example.com",
            expires_at=datetime.now(timezone.utc),
            inbox_hash="plain-hash",
            encrypted=False,
            _keypair=None,
            _api_client=mock_api_client,
            _strategy=MagicMock(),
        )

        await inbox.delete_email("email-1")

        mock_api_client.delete_email.assert_called_once_with("plain@example.com", "email-1")

    @pytest.mark.asyncio
    async def test_plain_inbox_mark_email_as_read(self) -> None:
        """Test that plain inbox can mark emails as read."""
        mock_api_client = MagicMock()
        mock_api_client.mark_email_as_read = AsyncMock()

        inbox = Inbox(
            email_address="plain@example.com",
            expires_at=datetime.now(timezone.utc),
            inbox_hash="plain-hash",
            encrypted=False,
            _keypair=None,
            _api_client=mock_api_client,
            _strategy=MagicMock(),
        )

        await inbox.mark_email_as_read("email-1")

        mock_api_client.mark_email_as_read.assert_called_once_with("plain@example.com", "email-1")
