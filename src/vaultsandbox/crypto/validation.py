"""Encrypted payload validation for VaultSandbox SDK.

This module implements validation per Section 8 of the VaultSandbox
Cryptographic Protocol Specification.
"""

from __future__ import annotations

from ..errors import (
    InvalidAlgorithmError,
    InvalidPayloadError,
    InvalidSizeError,
    ServerKeyMismatchError,
    UnsupportedVersionError,
)
from ..types import EncryptedPayload
from .constants import (
    AES_GCM_NONCE_SIZE,
    EXPECTED_AEAD,
    EXPECTED_KDF,
    EXPECTED_KEM,
    EXPECTED_SIG,
    MLDSA65_PUBLIC_KEY_SIZE,
    MLDSA65_SIGNATURE_SIZE,
    MLKEM768_CIPHERTEXT_SIZE,
    PROTOCOL_VERSION,
)
from .utils import from_base64url


def validate_payload(
    encrypted_data: EncryptedPayload,
    pinned_server_key: str | None = None,
) -> None:
    """Validate an encrypted payload per Section 8.1.

    Validation steps (must be performed in order):
    1. Parse payload - Decode JSON and validate structure
    2. Validate version - Verify v == 1
    3. Validate algorithms - Verify all algorithm fields match expected values
    4. Validate sizes - Verify decoded binary fields have correct sizes
    5. Verify server key - Compare server_sig_pk against pinned key (if provided)

    Args:
        encrypted_data: The encrypted payload to validate.
        pinned_server_key: The pinned server signature public key (base64url).
            If provided, the payload's server_sig_pk must match exactly.

    Raises:
        InvalidPayloadError: If required fields are missing.
        UnsupportedVersionError: If version is not 1.
        InvalidAlgorithmError: If algorithms don't match expected values.
        InvalidSizeError: If decoded fields have incorrect sizes.
        ServerKeyMismatchError: If server key doesn't match pinned key.
    """
    # Step 1: Validate structure - check required fields
    _validate_structure(encrypted_data)

    # Step 2: Validate version
    _validate_version(encrypted_data)

    # Step 3: Validate algorithms
    _validate_algorithms(encrypted_data)

    # Step 4: Validate sizes
    _validate_sizes(encrypted_data)

    # Step 5: Verify server key (if pinned key provided)
    if pinned_server_key is not None:
        _validate_server_key(encrypted_data, pinned_server_key)


def _validate_structure(encrypted_data: EncryptedPayload) -> None:
    """Validate payload structure - all required fields present."""
    required_fields = ["v", "algs", "ct_kem", "nonce", "aad", "ciphertext", "sig", "server_sig_pk"]

    for field in required_fields:
        if field not in encrypted_data:
            raise InvalidPayloadError(f"Missing required field: {field}")

    # Validate algs structure
    algs = encrypted_data.get("algs")
    if not isinstance(algs, dict):
        raise InvalidPayloadError("Field 'algs' must be an object")

    required_alg_fields = ["kem", "sig", "aead", "kdf"]
    for field in required_alg_fields:
        if field not in algs:
            raise InvalidPayloadError(f"Missing required field: algs.{field}")


def _validate_version(encrypted_data: EncryptedPayload) -> None:
    """Validate protocol version is 1."""
    version = encrypted_data.get("v")
    if version != PROTOCOL_VERSION:
        raise UnsupportedVersionError(
            f"Unsupported protocol version: {version}, expected {PROTOCOL_VERSION}"
        )


def _validate_algorithms(encrypted_data: EncryptedPayload) -> None:
    """Validate algorithm identifiers match expected values."""
    algs = encrypted_data["algs"]

    if algs.get("kem") != EXPECTED_KEM:
        raise InvalidAlgorithmError(
            f"Unsupported KEM algorithm: {algs.get('kem')}, expected {EXPECTED_KEM}"
        )

    if algs.get("sig") != EXPECTED_SIG:
        raise InvalidAlgorithmError(
            f"Unsupported signature algorithm: {algs.get('sig')}, expected {EXPECTED_SIG}"
        )

    if algs.get("aead") != EXPECTED_AEAD:
        raise InvalidAlgorithmError(
            f"Unsupported AEAD algorithm: {algs.get('aead')}, expected {EXPECTED_AEAD}"
        )

    if algs.get("kdf") != EXPECTED_KDF:
        raise InvalidAlgorithmError(
            f"Unsupported KDF algorithm: {algs.get('kdf')}, expected {EXPECTED_KDF}"
        )


def _validate_sizes(encrypted_data: EncryptedPayload) -> None:
    """Validate decoded binary fields have correct sizes per Section 5.3."""
    # Validate ct_kem size (1088 bytes)
    try:
        ct_kem = from_base64url(encrypted_data["ct_kem"])
        if len(ct_kem) != MLKEM768_CIPHERTEXT_SIZE:
            raise InvalidSizeError(
                f"Invalid ct_kem size: {len(ct_kem)} bytes, expected {MLKEM768_CIPHERTEXT_SIZE}"
            )
    except InvalidSizeError:
        raise
    except Exception as e:
        raise InvalidPayloadError(f"Failed to decode ct_kem: {e}") from e

    # Validate nonce size (12 bytes)
    try:
        nonce = from_base64url(encrypted_data["nonce"])
        if len(nonce) != AES_GCM_NONCE_SIZE:
            raise InvalidSizeError(
                f"Invalid nonce size: {len(nonce)} bytes, expected {AES_GCM_NONCE_SIZE}"
            )
    except InvalidSizeError:
        raise
    except Exception as e:
        raise InvalidPayloadError(f"Failed to decode nonce: {e}") from e

    # Validate sig size (3309 bytes)
    try:
        sig = from_base64url(encrypted_data["sig"])
        if len(sig) != MLDSA65_SIGNATURE_SIZE:
            raise InvalidSizeError(
                f"Invalid signature size: {len(sig)} bytes, expected {MLDSA65_SIGNATURE_SIZE}"
            )
    except InvalidSizeError:
        raise
    except Exception as e:
        raise InvalidPayloadError(f"Failed to decode sig: {e}") from e

    # Validate server_sig_pk size (1952 bytes)
    try:
        server_sig_pk = from_base64url(encrypted_data["server_sig_pk"])
        if len(server_sig_pk) != MLDSA65_PUBLIC_KEY_SIZE:
            raise InvalidSizeError(
                f"Invalid server_sig_pk size: {len(server_sig_pk)} bytes, "
                f"expected {MLDSA65_PUBLIC_KEY_SIZE}"
            )
    except InvalidSizeError:
        raise
    except Exception as e:
        raise InvalidPayloadError(f"Failed to decode server_sig_pk: {e}") from e


def _validate_server_key(encrypted_data: EncryptedPayload, pinned_server_key: str) -> None:
    """Validate server key matches pinned key from inbox creation.

    Per Section 8.2: Implementations MUST use constant-time comparison
    for server key verification.
    """
    payload_server_key = encrypted_data.get("server_sig_pk", "")

    # Use constant-time comparison via hmac.compare_digest
    import hmac

    # Compare the base64url strings directly (both should be base64url encoded)
    if not hmac.compare_digest(payload_server_key, pinned_server_key):
        raise ServerKeyMismatchError(
            "Server public key in payload does not match pinned server key from inbox creation"
        )
