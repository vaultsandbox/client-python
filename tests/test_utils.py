"""Tests for utility modules."""

import base64
import json
import re
from unittest.mock import MagicMock

import pytest

from vaultsandbox.types import WaitForEmailOptions
from vaultsandbox.utils.email_utils import (
    decode_plain_email_response,
    decrypt_email_response,
    matches_filter,
    parse_attachments,
)
from vaultsandbox.utils.sleep import sleep


class TestSleep:
    """Tests for the sleep utility."""

    @pytest.mark.asyncio
    async def test_sleep_completes(self) -> None:
        """Test that sleep completes after the specified duration."""
        # Sleep for 10ms - just verify it completes without error
        await sleep(10)

    @pytest.mark.asyncio
    async def test_sleep_zero(self) -> None:
        """Test that sleep with zero milliseconds completes immediately."""
        await sleep(0)


class TestParseAttachments:
    """Tests for the parse_attachments utility."""

    def test_invalid_base64_content_returns_empty_bytes(self) -> None:
        """Test that invalid base64 content results in empty bytes."""
        attachments_data = [
            {
                "filename": "test.txt",
                "contentType": "text/plain",
                "size": 100,
                "content": "!!!invalid-base64!!!",
            }
        ]
        result = parse_attachments(attachments_data)
        assert len(result) == 1
        assert result[0].filename == "test.txt"
        assert result[0].content == b""


class TestMatchesFilter:
    """Tests for the matches_filter utility."""

    def _create_mock_email(
        self, subject: str | None = "Test Subject", from_address: str | None = "sender@example.com"
    ) -> MagicMock:
        """Create a mock Email object for testing."""
        email = MagicMock()
        email.subject = subject
        email.from_address = from_address
        return email

    def test_regex_subject_no_match(self) -> None:
        """Test that regex subject pattern returns False when no match."""
        email = self._create_mock_email(subject="Hello World")
        options = WaitForEmailOptions(subject=re.compile(r"Goodbye"))
        assert matches_filter(email, options) is False

    def test_string_from_address_no_match(self) -> None:
        """Test that string from_address returns False when no match."""
        email = self._create_mock_email(from_address="other@example.com")
        options = WaitForEmailOptions(from_address="sender@test.com")
        assert matches_filter(email, options) is False

    def test_regex_from_address_no_match(self) -> None:
        """Test that regex from_address pattern returns False when no match."""
        email = self._create_mock_email(from_address="other@example.com")
        options = WaitForEmailOptions(from_address=re.compile(r"sender@test\.com"))
        assert matches_filter(email, options) is False


class TestDecodePlainEmailResponse:
    """Tests for decode_plain_email_response function."""

    def test_decode_plain_email_response(self) -> None:
        """Test decoding a plain (base64) email response."""
        metadata = {
            "from": "sender@example.com",
            "to": ["recipient@example.com"],
            "subject": "Test Subject",
            "receivedAt": "2025-01-01T12:00:00Z",
        }
        parsed = {
            "text": "Hello, World!",
            "html": "<p>Hello, World!</p>",
            "headers": {"X-Custom": "value"},
            "links": ["https://example.com"],
            "authResults": {
                "spf": {"status": "pass", "domain": "example.com"},
                "dkim": [],
                "dmarc": {"status": "pass"},
            },
            "metadata": {"extra": "data"},
        }

        email_response = {
            "id": "email-123",
            "inboxId": "inbox-456",
            "receivedAt": "2025-01-01T12:00:00Z",
            "isRead": False,
            "metadata": base64.b64encode(json.dumps(metadata).encode()).decode(),
            "parsed": base64.b64encode(json.dumps(parsed).encode()).decode(),
        }

        result = decode_plain_email_response(email_response)

        assert result["id"] == "email-123"
        assert result["inbox_id"] == "inbox-456"
        assert result["from_address"] == "sender@example.com"
        assert result["to"] == ["recipient@example.com"]
        assert result["subject"] == "Test Subject"
        assert result["text"] == "Hello, World!"
        assert result["html"] == "<p>Hello, World!</p>"
        assert result["headers"] == {"X-Custom": "value"}
        assert result["links"] == ["https://example.com"]
        assert result["is_read"] is False
        assert result["parsed_metadata"] == {"extra": "data"}

    def test_decode_plain_email_response_empty_fields(self) -> None:
        """Test decoding a plain email response with empty/missing fields."""
        email_response = {
            "id": "email-123",
            "metadata": "",
            "parsed": "",
        }

        result = decode_plain_email_response(email_response)

        assert result["id"] == "email-123"
        assert result["from_address"] == ""
        assert result["to"] == []
        assert result["subject"] == ""
        assert result["text"] is None
        assert result["html"] is None


class TestDecryptEmailResponsePlain:
    """Tests for decrypt_email_response with plain (non-encrypted) emails."""

    def test_decrypt_email_response_plain_email(self) -> None:
        """Test decrypt_email_response returns decoded data for plain email."""
        metadata = {
            "from": "sender@example.com",
            "to": ["recipient@example.com"],
            "subject": "Plain Email",
            "receivedAt": "2025-01-01T12:00:00Z",
        }
        parsed = {
            "text": "Plain text body",
            "html": None,
            "headers": {},
            "links": [],
        }

        # Plain email response uses 'metadata' and 'parsed' fields (not encrypted ones)
        email_response = {
            "id": "email-plain",
            "inboxId": "inbox-plain",
            "receivedAt": "2025-01-01T12:00:00Z",
            "isRead": True,
            "metadata": base64.b64encode(json.dumps(metadata).encode()).decode(),
            "parsed": base64.b64encode(json.dumps(parsed).encode()).decode(),
        }

        # No keypair needed for plain emails
        result = decrypt_email_response(email_response, keypair=None)

        assert result["id"] == "email-plain"
        assert result["from_address"] == "sender@example.com"
        assert result["subject"] == "Plain Email"
        assert result["text"] == "Plain text body"
        assert result["is_read"] is True

    def test_decrypt_email_response_encrypted_without_keypair_raises(self) -> None:
        """Test decrypt_email_response raises error for encrypted email without keypair."""
        # Encrypted email response has 'encryptedMetadata' field
        email_response = {
            "id": "email-encrypted",
            "encryptedMetadata": {"v": 1, "algs": {}},
            "encryptedParsed": {"v": 1, "algs": {}},
        }

        with pytest.raises(RuntimeError, match="no keypair provided"):
            decrypt_email_response(email_response, keypair=None)
