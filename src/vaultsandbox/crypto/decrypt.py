"""Decryption operations for VaultSandbox SDK."""

from __future__ import annotations

import json
from typing import Any, cast

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqcrypto.kem.ml_kem_768 import decrypt as mlkem_decapsulate

from ..errors import DecryptionError, SignatureVerificationError
from ..types import EncryptedPayload
from .keypair import Keypair, derive_key
from .signature import verify_signature
from .utils import from_base64url


def decrypt(encrypted_data: EncryptedPayload, keypair: Keypair) -> bytes:
    """Decrypt an encrypted payload.

    CRITICAL: Signature is verified BEFORE decryption.

    Args:
        encrypted_data: The encrypted payload from the server.
        keypair: The keypair to use for decryption.

    Returns:
        The decrypted plaintext bytes.

    Raises:
        SignatureVerificationError: If signature verification fails.
        DecryptionError: If decryption fails.
    """
    try:
        # Step 1: Verify signature FIRST (security-critical)
        verify_signature(encrypted_data)

        # Step 2: KEM decapsulation
        ct_kem = from_base64url(encrypted_data["ct_kem"])
        shared_secret = mlkem_decapsulate(keypair.secret_key, ct_kem)

        # Step 3: Key derivation (HKDF-SHA-512)
        aad = from_base64url(encrypted_data["aad"])
        aes_key = derive_key(bytes(shared_secret), ct_kem, aad)

        # Step 4: AES-256-GCM decryption
        nonce = from_base64url(encrypted_data["nonce"])
        ciphertext = from_base64url(encrypted_data["ciphertext"])

        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)

        return plaintext

    except SignatureVerificationError:
        raise
    except DecryptionError:
        raise
    except Exception as e:
        raise DecryptionError(f"Decryption failed: {e}") from e


def decrypt_json(
    encrypted_data: EncryptedPayload,
    keypair: Keypair,
    context: str = "content",
) -> dict[str, Any]:
    """Decrypt and parse JSON content.

    Args:
        encrypted_data: The encrypted payload.
        keypair: The keypair to use for decryption.
        context: Description of content type for error messages.

    Returns:
        The decrypted content as a dictionary.

    Raises:
        SignatureVerificationError: If signature verification fails.
        DecryptionError: If decryption or parsing fails.
    """
    try:
        plaintext = decrypt(encrypted_data, keypair)
        return cast(dict[str, Any], json.loads(plaintext.decode("utf-8")))
    except (SignatureVerificationError, DecryptionError):
        raise
    except json.JSONDecodeError as e:
        raise DecryptionError(f"Failed to parse decrypted {context} as JSON: {e}") from e


def decrypt_metadata(encrypted_data: EncryptedPayload, keypair: Keypair) -> dict[str, Any]:
    """Decrypt and parse email metadata.

    Args:
        encrypted_data: The encrypted metadata payload.
        keypair: The keypair to use for decryption.

    Returns:
        The decrypted metadata as a dictionary.

    Raises:
        SignatureVerificationError: If signature verification fails.
        DecryptionError: If decryption or parsing fails.
    """
    return decrypt_json(encrypted_data, keypair, context="metadata")


def decrypt_parsed(encrypted_data: EncryptedPayload, keypair: Keypair) -> dict[str, Any]:
    """Decrypt and parse email content.

    Args:
        encrypted_data: The encrypted parsed content payload.
        keypair: The keypair to use for decryption.

    Returns:
        The decrypted parsed content as a dictionary.

    Raises:
        SignatureVerificationError: If signature verification fails.
        DecryptionError: If decryption or parsing fails.
    """
    return decrypt_json(encrypted_data, keypair, context="content")


def decrypt_raw(encrypted_data: EncryptedPayload, keypair: Keypair) -> str:
    """Decrypt raw email content.

    Args:
        encrypted_data: The encrypted raw email payload.
        keypair: The keypair to use for decryption.

    Returns:
        The decrypted raw email as a string.

    Raises:
        SignatureVerificationError: If signature verification fails.
        DecryptionError: If decryption fails.
    """
    import base64

    try:
        plaintext = decrypt(encrypted_data, keypair)
        # The raw email content is base64 encoded in the encrypted payload
        raw_b64 = plaintext.decode("utf-8")
        raw_bytes = base64.b64decode(raw_b64)
        return raw_bytes.decode("utf-8")
    except (SignatureVerificationError, DecryptionError):
        raise
    except (UnicodeDecodeError, ValueError) as e:
        raise DecryptionError(f"Failed to decode decrypted raw email: {e}") from e
