"""Decryption operations for VaultSandbox SDK.

Implements the decryption process per Section 8 of the VaultSandbox
Cryptographic Protocol Specification.
"""

from __future__ import annotations

import json
from typing import Any, cast

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqcrypto.kem.ml_kem_768 import decrypt as mlkem_decapsulate

from ..errors import (
    DecryptionError,
    InvalidAlgorithmError,
    InvalidPayloadError,
    InvalidSizeError,
    ServerKeyMismatchError,
    SignatureVerificationError,
    UnsupportedVersionError,
)
from ..types import EncryptedPayload
from .keypair import Keypair, derive_key
from .signature import verify_signature
from .utils import from_base64url
from .validation import validate_payload


def decrypt(
    encrypted_data: EncryptedPayload,
    keypair: Keypair,
    pinned_server_key: str | None = None,
) -> bytes:
    """Decrypt an encrypted payload.

    Implements the decryption process per Section 8.1:
    1. Parse payload - Validate structure
    2. Validate version - Verify v == 1
    3. Validate algorithms - Verify all algorithm fields match
    4. Validate sizes - Verify decoded binary fields have correct sizes
    5. Verify server key - Compare against pinned key from inbox creation
    6. Verify signature - BEFORE decryption (security-critical)
    7. Decapsulate - ML-KEM decapsulation
    8. Derive AES key - HKDF-SHA-512
    9. Decrypt - AES-256-GCM

    Args:
        encrypted_data: The encrypted payload from the server.
        keypair: The keypair to use for decryption.
        pinned_server_key: The pinned server signature public key (base64url)
            from inbox creation. If provided, validates server key matches.

    Returns:
        The decrypted plaintext bytes.

    Raises:
        InvalidPayloadError: If payload structure is invalid.
        UnsupportedVersionError: If protocol version is not 1.
        InvalidAlgorithmError: If algorithms don't match expected values.
        InvalidSizeError: If decoded fields have incorrect sizes.
        ServerKeyMismatchError: If server key doesn't match pinned key.
        SignatureVerificationError: If signature verification fails.
        DecryptionError: If decryption fails.
    """
    try:
        # Steps 1-5: Validate payload (per Section 8.1)
        validate_payload(encrypted_data, pinned_server_key)

        # Step 6: Verify signature FIRST (security-critical, per Section 8.2)
        verify_signature(encrypted_data)

        # Step 7: KEM decapsulation
        ct_kem = from_base64url(encrypted_data["ct_kem"])
        shared_secret = mlkem_decapsulate(keypair.secret_key, ct_kem)

        # Step 8: Key derivation (HKDF-SHA-512)
        aad = from_base64url(encrypted_data["aad"])
        aes_key = derive_key(bytes(shared_secret), ct_kem, aad)

        # Step 9: AES-256-GCM decryption
        nonce = from_base64url(encrypted_data["nonce"])
        ciphertext = from_base64url(encrypted_data["ciphertext"])

        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)

        return plaintext

    except (
        InvalidPayloadError,
        UnsupportedVersionError,
        InvalidAlgorithmError,
        InvalidSizeError,
        ServerKeyMismatchError,
        SignatureVerificationError,
    ):
        # Re-raise validation and signature errors as-is
        raise
    except DecryptionError:
        raise
    except Exception as e:
        # Per Section 8.2: Use generic error message to prevent oracle attacks
        raise DecryptionError("Decryption failed") from e


def decrypt_json(
    encrypted_data: EncryptedPayload,
    keypair: Keypair,
    context: str = "content",
    pinned_server_key: str | None = None,
) -> dict[str, Any]:
    """Decrypt and parse JSON content.

    Args:
        encrypted_data: The encrypted payload.
        keypair: The keypair to use for decryption.
        context: Description of content type for error messages.
        pinned_server_key: The pinned server signature public key (base64url).

    Returns:
        The decrypted content as a dictionary.

    Raises:
        SignatureVerificationError: If signature verification fails.
        DecryptionError: If decryption or parsing fails.
    """
    try:
        plaintext = decrypt(encrypted_data, keypair, pinned_server_key)
        return cast(dict[str, Any], json.loads(plaintext.decode("utf-8")))
    except (
        InvalidPayloadError,
        UnsupportedVersionError,
        InvalidAlgorithmError,
        InvalidSizeError,
        ServerKeyMismatchError,
        SignatureVerificationError,
        DecryptionError,
    ):
        raise
    except json.JSONDecodeError as e:
        raise DecryptionError(f"Failed to parse decrypted {context} as JSON: {e}") from e


def decrypt_metadata(
    encrypted_data: EncryptedPayload,
    keypair: Keypair,
    pinned_server_key: str | None = None,
) -> dict[str, Any]:
    """Decrypt and parse email metadata.

    Args:
        encrypted_data: The encrypted metadata payload.
        keypair: The keypair to use for decryption.
        pinned_server_key: The pinned server signature public key (base64url).

    Returns:
        The decrypted metadata as a dictionary.

    Raises:
        SignatureVerificationError: If signature verification fails.
        DecryptionError: If decryption or parsing fails.
    """
    return decrypt_json(
        encrypted_data, keypair, context="metadata", pinned_server_key=pinned_server_key
    )


def decrypt_parsed(
    encrypted_data: EncryptedPayload,
    keypair: Keypair,
    pinned_server_key: str | None = None,
) -> dict[str, Any]:
    """Decrypt and parse email content.

    Args:
        encrypted_data: The encrypted parsed content payload.
        keypair: The keypair to use for decryption.
        pinned_server_key: The pinned server signature public key (base64url).

    Returns:
        The decrypted parsed content as a dictionary.

    Raises:
        SignatureVerificationError: If signature verification fails.
        DecryptionError: If decryption or parsing fails.
    """
    return decrypt_json(
        encrypted_data, keypair, context="content", pinned_server_key=pinned_server_key
    )


def decrypt_raw(
    encrypted_data: EncryptedPayload,
    keypair: Keypair,
    pinned_server_key: str | None = None,
) -> str:
    """Decrypt raw email content.

    Args:
        encrypted_data: The encrypted raw email payload.
        keypair: The keypair to use for decryption.
        pinned_server_key: The pinned server signature public key (base64url).

    Returns:
        The decrypted raw email as a string.

    Raises:
        SignatureVerificationError: If signature verification fails.
        DecryptionError: If decryption fails.
    """
    import base64

    try:
        plaintext = decrypt(encrypted_data, keypair, pinned_server_key)
        # The raw email content is base64 encoded in the encrypted payload
        raw_b64 = plaintext.decode("utf-8")
        raw_bytes = base64.b64decode(raw_b64)
        return raw_bytes.decode("utf-8")
    except (
        InvalidPayloadError,
        UnsupportedVersionError,
        InvalidAlgorithmError,
        InvalidSizeError,
        ServerKeyMismatchError,
        SignatureVerificationError,
        DecryptionError,
    ):
        raise
    except (UnicodeDecodeError, ValueError) as e:
        raise DecryptionError(f"Failed to decode decrypted raw email: {e}") from e
