"""Base64 encoding/decoding utilities for VaultSandbox SDK."""

import base64
import re

# Valid Base64URL alphabet per RFC 4648 Section 5
# Does NOT include +, /, or = (padding is stripped)
_BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9\-_]*$")


class Base64URLDecodeError(ValueError):
    """Error raised when Base64URL decoding fails due to invalid characters."""

    pass


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

    Per VaultSandbox spec Section 2.2:
    - Use `-` instead of `+`
    - Use `_` instead of `/`
    - Do NOT include `=` padding characters
    - Implementations MUST reject input containing `+`, `/`, or `=`

    Args:
        s: The base64url string to decode.

    Returns:
        The decoded bytes.

    Raises:
        Base64URLDecodeError: If the input contains invalid characters (+, /, =).
    """
    # Validate input does not contain forbidden characters
    if not _BASE64URL_PATTERN.match(s):
        # Identify specific invalid characters for error message
        invalid_chars = set()
        if "+" in s:
            invalid_chars.add("+")
        if "/" in s:
            invalid_chars.add("/")
        if "=" in s:
            invalid_chars.add("=")
        if invalid_chars:
            raise Base64URLDecodeError(
                f"Invalid Base64URL: contains forbidden characters {invalid_chars}. "
                "Use '-' instead of '+', '_' instead of '/', and no padding."
            )
        # Other invalid characters
        raise Base64URLDecodeError("Invalid Base64URL: contains non-Base64URL characters")

    # Add padding internally for decoding
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
