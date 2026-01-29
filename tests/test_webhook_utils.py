"""Tests for webhook utility functions."""

from __future__ import annotations

import hashlib
import hmac
import time

import pytest

from vaultsandbox.errors import WebhookSignatureVerificationError
from vaultsandbox.utils.webhook_utils import (
    is_timestamp_valid,
    verify_webhook_signature,
)


class TestVerifyWebhookSignatureValidation:
    """Tests for input validation in verify_webhook_signature."""

    def test_empty_body_raises_error(self) -> None:
        """Test that empty request body raises error (line 64)."""
        with pytest.raises(WebhookSignatureVerificationError) as exc_info:
            verify_webhook_signature("", "sha256=abc", "123456", "secret")

        assert "Empty request body" in str(exc_info.value)

    def test_missing_signature_raises_error(self) -> None:
        """Test that missing signature raises error (line 66)."""
        with pytest.raises(WebhookSignatureVerificationError) as exc_info:
            verify_webhook_signature("body", "", "123456", "secret")

        assert "Missing signature header" in str(exc_info.value)

    def test_missing_timestamp_raises_error(self) -> None:
        """Test that missing timestamp raises error (line 68)."""
        with pytest.raises(WebhookSignatureVerificationError) as exc_info:
            verify_webhook_signature("body", "sha256=abc", "", "secret")

        assert "Missing timestamp header" in str(exc_info.value)

    def test_missing_secret_raises_error(self) -> None:
        """Test that missing secret raises error (line 70)."""
        with pytest.raises(WebhookSignatureVerificationError) as exc_info:
            verify_webhook_signature("body", "sha256=abc", "123456", "")

        assert "Missing webhook secret" in str(exc_info.value)

    def test_invalid_timestamp_format_raises_error(self) -> None:
        """Test that invalid timestamp format raises error (lines 80-81)."""
        with pytest.raises(WebhookSignatureVerificationError) as exc_info:
            verify_webhook_signature("body", "sha256=abc", "not-a-number", "secret")

        assert "Invalid timestamp format" in str(exc_info.value)

    def test_invalid_utf8_bytes_raises_error(self) -> None:
        """Test that invalid UTF-8 bytes in body raises error (lines 78-79)."""
        # Create invalid UTF-8 bytes (0xff 0xfe is not valid UTF-8)
        invalid_bytes = b"\xff\xfe invalid utf-8"

        with pytest.raises(WebhookSignatureVerificationError) as exc_info:
            verify_webhook_signature(invalid_bytes, "sha256=abc", "123456", "secret")

        assert "Invalid UTF-8 encoding" in str(exc_info.value)

    def test_signature_without_prefix(self) -> None:
        """Test that signature without sha256= prefix works (line 95)."""
        secret = "whsec_test_secret"
        body = '{"test": "data"}'
        timestamp = str(int(time.time()))

        # Compute expected signature
        signed_payload = f"{timestamp}.{body}"
        expected_sig = hmac.new(
            secret.encode("utf-8"),
            signed_payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        # Pass signature without the "sha256=" prefix
        result = verify_webhook_signature(body, expected_sig, timestamp, secret)

        assert result is True


class TestWebhookTimestampTolerance:
    """Tests for webhook timestamp tolerance and replay attack prevention."""

    def _create_valid_signature(self, body: str, timestamp: str, secret: str) -> str:
        """Create a valid HMAC-SHA256 signature for testing."""
        signed_payload = f"{timestamp}.{body}"
        return (
            "sha256="
            + hmac.new(
                secret.encode("utf-8"),
                signed_payload.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
        )

    def test_timestamp_within_default_tolerance(self) -> None:
        """Test that timestamp within 60 second default tolerance is accepted."""
        secret = "whsec_test_secret"
        body = '{"test": "data"}'
        # Timestamp 30 seconds ago (within default 60s tolerance)
        timestamp = str(int(time.time()) - 30)
        signature = self._create_valid_signature(body, timestamp, secret)

        result = verify_webhook_signature(body, signature, timestamp, secret)
        assert result is True

    def test_replay_attack_rejected_with_default_tolerance(self) -> None:
        """Test that timestamps older than 60 seconds are rejected (replay attack)."""
        secret = "whsec_test_secret"
        body = '{"test": "data"}'
        # Timestamp 90 seconds ago (outside default 60s tolerance)
        timestamp = str(int(time.time()) - 90)
        signature = self._create_valid_signature(body, timestamp, secret)

        with pytest.raises(WebhookSignatureVerificationError) as exc_info:
            verify_webhook_signature(body, signature, timestamp, secret)

        assert "Timestamp outside tolerance window" in str(exc_info.value)

    def test_custom_tolerance_allows_older_timestamps(self) -> None:
        """Test that custom tolerance can allow older timestamps."""
        secret = "whsec_test_secret"
        body = '{"test": "data"}'
        # Timestamp 120 seconds ago
        timestamp = str(int(time.time()) - 120)
        signature = self._create_valid_signature(body, timestamp, secret)

        # With default tolerance (60s), this would be rejected
        with pytest.raises(WebhookSignatureVerificationError):
            verify_webhook_signature(body, signature, timestamp, secret)

        # With custom tolerance (180s), this should pass
        result = verify_webhook_signature(body, signature, timestamp, secret, tolerance_seconds=180)
        assert result is True

    def test_timestamp_in_future_within_tolerance(self) -> None:
        """Test that timestamps slightly in the future are accepted."""
        secret = "whsec_test_secret"
        body = '{"test": "data"}'
        # Timestamp 30 seconds in the future (within tolerance)
        timestamp = str(int(time.time()) + 30)
        signature = self._create_valid_signature(body, timestamp, secret)

        result = verify_webhook_signature(body, signature, timestamp, secret)
        assert result is True

    def test_timestamp_in_future_outside_tolerance(self) -> None:
        """Test that timestamps too far in the future are rejected."""
        secret = "whsec_test_secret"
        body = '{"test": "data"}'
        # Timestamp 90 seconds in the future (outside tolerance)
        timestamp = str(int(time.time()) + 90)
        signature = self._create_valid_signature(body, timestamp, secret)

        with pytest.raises(WebhookSignatureVerificationError) as exc_info:
            verify_webhook_signature(body, signature, timestamp, secret)

        assert "Timestamp outside tolerance window" in str(exc_info.value)

    def test_zero_tolerance_disables_timestamp_validation(self) -> None:
        """Test that tolerance_seconds=0 disables timestamp validation."""
        secret = "whsec_test_secret"
        body = '{"test": "data"}'
        # Very old timestamp (1 hour ago)
        timestamp = str(int(time.time()) - 3600)
        signature = self._create_valid_signature(body, timestamp, secret)

        # This should pass when timestamp validation is disabled
        result = verify_webhook_signature(body, signature, timestamp, secret, tolerance_seconds=0)
        assert result is True


class TestIsTimestampValid:
    """Tests for is_timestamp_valid helper function."""

    def test_timestamp_within_default_tolerance(self) -> None:
        """Test that timestamp within 60s default tolerance returns True."""
        timestamp = str(int(time.time()) - 30)
        assert is_timestamp_valid(timestamp) is True

    def test_timestamp_outside_default_tolerance(self) -> None:
        """Test that timestamp outside 60s default tolerance returns False."""
        timestamp = str(int(time.time()) - 90)
        assert is_timestamp_valid(timestamp) is False

    def test_custom_tolerance(self) -> None:
        """Test that custom tolerance works correctly."""
        timestamp = str(int(time.time()) - 120)
        # Should fail with default 60s
        assert is_timestamp_valid(timestamp) is False
        # Should pass with 180s tolerance
        assert is_timestamp_valid(timestamp, tolerance_seconds=180) is True

    def test_invalid_timestamp_returns_false(self) -> None:
        """Test that invalid timestamp format returns False."""
        assert is_timestamp_valid("not-a-number") is False
        assert is_timestamp_valid("") is False

    def test_none_timestamp_returns_false(self) -> None:
        """Test that None timestamp returns False."""
        assert is_timestamp_valid(None) is False  # type: ignore[arg-type]
