"""ML-DSA-65 signature verification for VaultSandbox SDK."""

from __future__ import annotations

from pqcrypto.sign.ml_dsa_65 import verify as mldsa_verify

from ..errors import SignatureVerificationError
from ..types import EncryptedPayload
from .constants import HKDF_CONTEXT, MLDSA65_PUBLIC_KEY_SIZE
from .utils import from_base64url


def build_transcript(encrypted_data: EncryptedPayload) -> bytes:
    """Build the transcript for signature verification.

    The transcript must be constructed byte-for-byte identical to the server.

    Args:
        encrypted_data: The encrypted payload from the server.

    Returns:
        The transcript bytes for signature verification.
    """
    # Version byte
    version_bytes = bytes([encrypted_data["v"]])

    # Algorithm ciphersuite string
    algs = encrypted_data["algs"]
    algs_ciphersuite = f"{algs['kem']}:{algs['sig']}:{algs['aead']}:{algs['kdf']}"
    algs_bytes = algs_ciphersuite.encode("utf-8")

    # Context string
    context_bytes = HKDF_CONTEXT.encode("utf-8")

    # Decode all base64url fields
    ct_kem = from_base64url(encrypted_data["ct_kem"])
    nonce = from_base64url(encrypted_data["nonce"])
    aad = from_base64url(encrypted_data["aad"])
    ciphertext = from_base64url(encrypted_data["ciphertext"])
    server_sig_pk = from_base64url(encrypted_data["server_sig_pk"])

    # Concatenate all parts
    return (
        version_bytes
        + algs_bytes
        + context_bytes
        + ct_kem
        + nonce
        + aad
        + ciphertext
        + server_sig_pk
    )


def validate_server_public_key(server_sig_pk: bytes) -> bool:
    """Validate the server's ML-DSA-65 public key format.

    Args:
        server_sig_pk: The server's signing public key.

    Returns:
        True if valid, False otherwise.
    """
    return len(server_sig_pk) == MLDSA65_PUBLIC_KEY_SIZE


def verify_signature(encrypted_data: EncryptedPayload) -> None:
    """Verify the ML-DSA-65 signature on encrypted data.

    CRITICAL: Always verify signature BEFORE decryption to detect tampering.

    Args:
        encrypted_data: The encrypted payload from the server.

    Raises:
        SignatureVerificationError: If signature verification fails.
    """
    try:
        # Decode signature and server public key
        signature = from_base64url(encrypted_data["sig"])
        server_sig_pk = from_base64url(encrypted_data["server_sig_pk"])

        # Validate server public key
        if not validate_server_public_key(server_sig_pk):
            raise SignatureVerificationError(
                f"Invalid server public key length: {len(server_sig_pk)}, "
                f"expected {MLDSA65_PUBLIC_KEY_SIZE}"
            )

        # Build transcript
        transcript = build_transcript(encrypted_data)

        # Verify signature using ML-DSA-65 (Dilithium3)
        # pqcrypto.sign.ml_dsa_65.verify raises ValueError if verification fails
        mldsa_verify(server_sig_pk, transcript, signature)

    except SignatureVerificationError:
        raise
    except ValueError as e:
        raise SignatureVerificationError(
            f"SIGNATURE VERIFICATION FAILED - Data may be tampered! Error: {e}"
        ) from e
    except Exception as e:
        raise SignatureVerificationError(
            f"SIGNATURE VERIFICATION FAILED - Data may be tampered! Error: {e}"
        ) from e


def verify_signature_safe(encrypted_data: EncryptedPayload) -> bool:
    """Verify the ML-DSA-65 signature without raising exceptions.

    Args:
        encrypted_data: The encrypted payload from the server.

    Returns:
        True if signature is valid, False otherwise.
    """
    try:
        verify_signature(encrypted_data)
        return True
    except SignatureVerificationError:
        return False
