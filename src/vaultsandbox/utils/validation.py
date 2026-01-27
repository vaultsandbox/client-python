"""Validation utilities for VaultSandbox SDK."""

from __future__ import annotations

import re

# Pattern for valid email IDs - alphanumeric, underscores, and hyphens
EMAIL_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")

# Pattern for valid webhook IDs - starts with 'whk_' prefix
WEBHOOK_ID_PATTERN = re.compile(r"^whk_[a-zA-Z0-9_-]+$")


def validate_email_id(email_id: str) -> None:
    """Validate email ID format.

    Args:
        email_id: The email ID to validate.

    Raises:
        ValueError: If the email ID format is invalid.
    """
    if not email_id:
        raise ValueError("Email ID cannot be empty")
    if not EMAIL_ID_PATTERN.match(email_id):
        raise ValueError(
            f"Invalid email ID format: {email_id!r}. "
            "Email ID must contain only alphanumeric characters, underscores, and hyphens."
        )


def validate_webhook_id(webhook_id: str) -> None:
    """Validate webhook ID format.

    Args:
        webhook_id: The webhook ID to validate.

    Raises:
        ValueError: If the webhook ID format is invalid.
    """
    if not webhook_id:
        raise ValueError("Webhook ID cannot be empty")
    if not WEBHOOK_ID_PATTERN.match(webhook_id):
        raise ValueError(
            f"Invalid webhook ID format: {webhook_id!r}. Webhook ID must start with 'whk_' prefix."
        )
