"""Datetime utilities for VaultSandbox SDK."""

from datetime import datetime

from ..errors import InvalidTimestampError


def parse_iso_timestamp(timestamp_str: str) -> datetime:
    """Parse an ISO 8601 timestamp string to datetime.

    Handles both 'Z' suffix and '+00:00' timezone formats.

    Args:
        timestamp_str: ISO 8601 formatted timestamp string.

    Returns:
        A datetime object.

    Raises:
        InvalidTimestampError: If the timestamp format is invalid.
    """
    try:
        if timestamp_str.endswith("Z"):
            timestamp_str = timestamp_str[:-1] + "+00:00"
        return datetime.fromisoformat(timestamp_str)
    except ValueError as e:
        raise InvalidTimestampError(f"Invalid timestamp format: {timestamp_str!r}") from e
