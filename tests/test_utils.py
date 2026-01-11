"""Tests for utility modules."""

import re
from unittest.mock import MagicMock

import pytest

from vaultsandbox.types import WaitForEmailOptions
from vaultsandbox.utils.email_utils import matches_filter, parse_attachments
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
