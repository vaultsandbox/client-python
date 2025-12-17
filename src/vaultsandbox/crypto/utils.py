"""Base64 encoding/decoding utilities for VaultSandbox SDK."""

import base64


def to_base64url(data: bytes) -> str:
    """Encode bytes to URL-safe base64 without padding.

    Args:
        data: The bytes to encode.

    Returns:
        URL-safe base64 string without padding.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def from_base64url(s: str) -> bytes:
    """Decode URL-safe base64 string to bytes.

    Handles missing padding automatically.

    Args:
        s: The base64url string to decode.

    Returns:
        The decoded bytes.
    """
    # Add padding if needed
    padding = 4 - (len(s) % 4)
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def to_base64(data: bytes) -> str:
    """Encode bytes to standard base64.

    Args:
        data: The bytes to encode.

    Returns:
        Standard base64 string with padding.
    """
    return base64.b64encode(data).decode("ascii")


def from_base64(s: str) -> bytes:
    """Decode standard base64 string to bytes.

    Args:
        s: The base64 string to decode.

    Returns:
        The decoded bytes.
    """
    return base64.b64decode(s)
