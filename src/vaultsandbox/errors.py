"""Error hierarchy for VaultSandbox SDK.

Error codes follow VaultSandbox Cryptographic Protocol Specification Appendix C.
"""

from __future__ import annotations


class VaultSandboxError(Exception):
    """Base exception for all VaultSandbox SDK errors."""

    pass


class ApiError(VaultSandboxError):
    """HTTP API error with status code.

    Attributes:
        status_code: The HTTP status code.
        message: The error message.
    """

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = message
        super().__init__(f"API Error ({status_code}): {message}")


class UnsupportedVersionError(VaultSandboxError):
    """Protocol or export version not supported (UNSUPPORTED_VERSION)."""

    pass


class InvalidPayloadError(VaultSandboxError):
    """Malformed JSON or missing required fields (INVALID_PAYLOAD)."""

    pass


class InvalidAlgorithmError(VaultSandboxError):
    """Unrecognized or unsupported algorithm (INVALID_ALGORITHM)."""

    pass


class InvalidSizeError(VaultSandboxError):
    """Decoded field has incorrect size (INVALID_SIZE)."""

    pass


class ServerKeyMismatchError(VaultSandboxError):
    """Server public key doesn't match pinned key (SERVER_KEY_MISMATCH)."""

    pass


class NetworkError(VaultSandboxError):
    """Network communication failure."""

    pass


class TimeoutError(VaultSandboxError):
    """Operation timeout."""

    pass


class InboxNotFoundError(VaultSandboxError):
    """Inbox not found (404)."""

    pass


class EmailNotFoundError(VaultSandboxError):
    """Email not found (404)."""

    pass


class InboxAlreadyExistsError(VaultSandboxError):
    """Inbox already exists during import."""

    pass


class InvalidImportDataError(VaultSandboxError):
    """Invalid data provided for inbox import."""

    pass


class DecryptionError(VaultSandboxError):
    """Cryptographic decryption failure."""

    pass


class SignatureVerificationError(VaultSandboxError):
    """Signature verification failure.

    CRITICAL: This error indicates potential tampering with the encrypted data.
    Should be logged immediately and never silently ignored.
    """

    pass


class SSEError(VaultSandboxError):
    """Server-Sent Events connection error."""

    pass


class StrategyError(VaultSandboxError):
    """Delivery strategy configuration or execution error."""

    pass
