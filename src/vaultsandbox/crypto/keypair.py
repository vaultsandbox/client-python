"""ML-KEM-768 keypair generation and key derivation for VaultSandbox SDK."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem.ml_kem_768 import generate_keypair as mlkem_generate_keypair

from .constants import (
    AES_KEY_SIZE,
    HKDF_CONTEXT,
    MLKEM768_CPA_PRIVATE_KEY_SIZE,
    MLKEM768_PUBLIC_KEY_SIZE,
    MLKEM768_SECRET_KEY_SIZE,
)
from .utils import to_base64url


@dataclass
class Keypair:
    """ML-KEM-768 keypair for encryption/decryption.

    Attributes:
        public_key: The public key bytes (1184 bytes).
        secret_key: The secret key bytes (2400 bytes).
        public_key_b64: Base64url-encoded public key.
    """

    public_key: bytes
    secret_key: bytes
    public_key_b64: str


def generate_keypair() -> Keypair:
    """Generate a new ML-KEM-768 keypair.

    Returns:
        A new Keypair instance with public and secret keys.
    """
    public_key, secret_key = mlkem_generate_keypair()
    return Keypair(
        public_key=bytes(public_key),
        secret_key=bytes(secret_key),
        public_key_b64=to_base64url(public_key),
    )


def validate_keypair(keypair: Keypair) -> bool:
    """Validate that a keypair has the correct structure and sizes.

    Args:
        keypair: The keypair to validate.

    Returns:
        True if valid, False otherwise.
    """
    if len(keypair.public_key) != MLKEM768_PUBLIC_KEY_SIZE:
        return False
    return len(keypair.secret_key) == MLKEM768_SECRET_KEY_SIZE


def derive_public_key_from_secret(secret_key: bytes) -> bytes:
    """Derive the public key from an ML-KEM-768 secret key.

    In ML-KEM-768, the secret key structure is:
      privateKey = cpaPrivateKey || cpaPublicKey || h || z
    Where:
      - cpaPrivateKey: 1152 bytes (12 * k * n / 8, k=3, n=256)
      - cpaPublicKey: 1184 bytes (the public key)
      - h: 32 bytes (hash of public key)
      - z: 32 bytes (random seed)

    The public key starts at offset 1152 and ends at offset 2336.

    Args:
        secret_key: The secret key bytes (2400 bytes).

    Returns:
        The public key bytes (1184 bytes).

    Raises:
        ValueError: If the secret key has invalid length.
    """
    if len(secret_key) != MLKEM768_SECRET_KEY_SIZE:
        raise ValueError(
            f"Invalid secret key length: {len(secret_key)}, expected {MLKEM768_SECRET_KEY_SIZE}"
        )
    # Public key is at offset 1152-2336 (after cpaPrivateKey, before h and z)
    return secret_key[
        MLKEM768_CPA_PRIVATE_KEY_SIZE : MLKEM768_CPA_PRIVATE_KEY_SIZE + MLKEM768_PUBLIC_KEY_SIZE
    ]


def derive_key(shared_secret: bytes, ct_kem: bytes, aad: bytes) -> bytes:
    """Derive an AES-256 key using HKDF-SHA-512.

    Args:
        shared_secret: The shared secret from KEM decapsulation.
        ct_kem: The KEM ciphertext (used as salt via SHA-256).
        aad: Additional authenticated data.

    Returns:
        A 32-byte AES-256 key.
    """
    # Salt is SHA-256 hash of KEM ciphertext
    salt = hashlib.sha256(ct_kem).digest()

    # Info construction: context || aad_length (4 bytes, big-endian) || aad
    context_bytes = HKDF_CONTEXT.encode("utf-8")
    aad_length = len(aad).to_bytes(4, "big")
    info = context_bytes + aad_length + aad

    # HKDF with SHA-512
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=AES_KEY_SIZE,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)
