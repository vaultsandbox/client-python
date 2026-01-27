"""Webhook utilities for signature verification."""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any

from ..errors import WebhookSignatureVerificationError


def verify_webhook_signature(
    raw_body: str | bytes,
    signature: str,
    timestamp: str,
    secret: str,
    *,
    tolerance_seconds: int = 60,
) -> bool:
    """Verify a webhook payload signature.

    All VaultSandbox webhook deliveries are signed using HMAC-SHA256.
    This function verifies that a payload is authentic and hasn't been tampered with.

    The signature is computed as:
        signed_payload = f"{timestamp}.{raw_body}"
        signature = HMAC-SHA256(signed_payload, secret)

    Args:
        raw_body: The raw request body as string or bytes.
        signature: The X-Vault-Signature header value (format: "sha256=<hex>").
        timestamp: The X-Vault-Timestamp header value (Unix timestamp).
        secret: The webhook signing secret (whsec_ prefix).
        tolerance_seconds: Maximum age of the timestamp in seconds (default: 60).
            Lower values are more secure against replay attacks but may cause
            issues with clock drift. Values above 120 are not recommended.
            Set to 0 to disable timestamp validation.

    Returns:
        True if the signature is valid.

    Raises:
        WebhookSignatureVerificationError: If verification fails.

    Example:
        ```python
        from vaultsandbox import verify_webhook_signature

        # In your webhook handler
        raw_body = request.get_data(as_text=True)
        signature = request.headers.get("X-Vault-Signature")
        timestamp = request.headers.get("X-Vault-Timestamp")

        try:
            verify_webhook_signature(raw_body, signature, timestamp, WEBHOOK_SECRET)
            # Signature is valid, process the event
            event = request.get_json()
        except WebhookSignatureVerificationError as e:
            # Invalid signature - reject the request
            return "Invalid signature", 401
        ```
    """
    # Validate inputs
    if not raw_body:
        raise WebhookSignatureVerificationError("Empty request body")
    if not signature:
        raise WebhookSignatureVerificationError("Missing signature header")
    if not timestamp:
        raise WebhookSignatureVerificationError("Missing timestamp header")
    if not secret:
        raise WebhookSignatureVerificationError("Missing webhook secret")

    # Convert bytes to string if needed
    if isinstance(raw_body, bytes):
        try:
            raw_body = raw_body.decode("utf-8")
        except UnicodeDecodeError:
            raise WebhookSignatureVerificationError(
                "Invalid UTF-8 encoding in request body"
            ) from None

    # Validate timestamp to prevent replay attacks
    if tolerance_seconds > 0:
        try:
            webhook_time = int(timestamp)
        except ValueError:
            raise WebhookSignatureVerificationError(
                f"Invalid timestamp format: {timestamp}"
            ) from None

        current_time = int(time.time())
        if abs(current_time - webhook_time) > tolerance_seconds:
            raise WebhookSignatureVerificationError(
                f"Timestamp outside tolerance window ({tolerance_seconds}s)"
            )

    # Extract the hex signature from the header (remove "sha256=" prefix if present)
    actual_signature = signature[7:] if signature.startswith("sha256=") else signature

    # Compute expected signature
    signed_payload = f"{timestamp}.{raw_body}"
    expected_signature = hmac.new(
        secret.encode("utf-8"),
        signed_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    # Constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(expected_signature, actual_signature):
        raise WebhookSignatureVerificationError("Invalid signature")

    return True


def is_timestamp_valid(timestamp: str, tolerance_seconds: int = 60) -> bool:
    """Check if a webhook timestamp is within the tolerance window.

    Args:
        timestamp: Unix timestamp as string.
        tolerance_seconds: Maximum age in seconds (default: 60).
            Lower values are more secure against replay attacks but may cause
            issues with clock drift. Values above 120 are not recommended.

    Returns:
        True if the timestamp is within tolerance, False otherwise.

    Example:
        ```python
        from vaultsandbox import is_timestamp_valid

        timestamp = request.headers.get("X-Vault-Timestamp")
        if not is_timestamp_valid(timestamp):
            return "Timestamp expired", 401
        ```
    """
    try:
        webhook_time = int(timestamp)
    except (ValueError, TypeError):
        return False

    current_time = int(time.time())
    return abs(current_time - webhook_time) <= tolerance_seconds


def construct_webhook_event(payload: dict[str, Any]) -> dict[str, Any]:
    """Parse a webhook payload into a structured event.

    This is a convenience function to help work with webhook payloads.
    All events follow the standard envelope format:

    {
        "id": "evt_...",
        "object": "event",
        "createdAt": 1705420800,
        "type": "email.received",
        "data": { ... event-specific data ... }
    }

    Args:
        payload: The parsed JSON webhook payload.

    Returns:
        The same payload (for chaining) after validating structure.

    Raises:
        WebhookSignatureVerificationError: If the payload is malformed.

    Example:
        ```python
        import json
        from vaultsandbox import verify_webhook_signature, construct_webhook_event

        verify_webhook_signature(raw_body, signature, timestamp, secret)
        event = construct_webhook_event(json.loads(raw_body))

        if event["type"] == "email.received":
            email_data = event["data"]
            print(f"New email from {email_data['from']['address']}")
        ```
    """
    required_fields = ["id", "object", "createdAt", "type", "data"]

    for field in required_fields:
        if field not in payload:
            raise WebhookSignatureVerificationError(
                f"Malformed webhook payload: missing '{field}' field"
            )

    if payload["object"] != "event":
        raise WebhookSignatureVerificationError(f"Unexpected object type: {payload['object']}")

    return payload
