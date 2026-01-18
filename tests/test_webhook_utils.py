"""Tests for webhook utility functions."""

from __future__ import annotations

import hashlib
import hmac
import time

import pytest

from vaultsandbox.errors import WebhookSignatureVerificationError
from vaultsandbox.utils.webhook_utils import verify_webhook_signature


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
