"""Cryptographic operations for VaultSandbox SDK.

This module implements cryptographic operations per the VaultSandbox
Cryptographic Protocol Specification.
"""

from .constants import (
    AES_GCM_NONCE_SIZE,
    AES_GCM_TAG_SIZE,
    AES_KEY_SIZE,
    ALGORITHM_SUITE,
    EXPECTED_AEAD,
    EXPECTED_KDF,
    EXPECTED_KEM,
    EXPECTED_SIG,
    EXPORT_VERSION,
    HKDF_CONTEXT,
    MLDSA65_PUBLIC_KEY_SIZE,
    MLDSA65_SIGNATURE_SIZE,
    MLKEM768_CIPHERTEXT_SIZE,
    MLKEM768_CPA_PRIVATE_KEY_SIZE,
    MLKEM768_PUBLIC_KEY_OFFSET,
    MLKEM768_PUBLIC_KEY_SIZE,
    MLKEM768_SECRET_KEY_SIZE,
    MLKEM768_SHARED_SECRET_SIZE,
    PROTOCOL_VERSION,
)
from .decrypt import decrypt, decrypt_metadata, decrypt_parsed, decrypt_raw
from .keypair import (
    Keypair,
    derive_key,
    derive_public_key_from_secret,
    generate_keypair,
    validate_keypair,
)
from .signature import (
    build_transcript,
    validate_server_public_key,
    verify_signature,
    verify_signature_safe,
)
from .utils import Base64URLDecodeError, from_base64, from_base64url, to_base64, to_base64url
from .validation import validate_payload

__all__ = [
    # Constants
    "AES_GCM_NONCE_SIZE",
    "AES_GCM_TAG_SIZE",
    "AES_KEY_SIZE",
    "ALGORITHM_SUITE",
    "EXPECTED_AEAD",
    "EXPECTED_KDF",
    "EXPECTED_KEM",
    "EXPECTED_SIG",
    "EXPORT_VERSION",
    "HKDF_CONTEXT",
    "MLDSA65_PUBLIC_KEY_SIZE",
    "MLDSA65_SIGNATURE_SIZE",
    "MLKEM768_CIPHERTEXT_SIZE",
    "MLKEM768_CPA_PRIVATE_KEY_SIZE",
    "MLKEM768_PUBLIC_KEY_OFFSET",
    "MLKEM768_PUBLIC_KEY_SIZE",
    "MLKEM768_SECRET_KEY_SIZE",
    "MLKEM768_SHARED_SECRET_SIZE",
    "PROTOCOL_VERSION",
    # Classes
    "Base64URLDecodeError",
    "Keypair",
    # Functions
    "build_transcript",
    "decrypt",
    "decrypt_metadata",
    "decrypt_parsed",
    "decrypt_raw",
    "derive_key",
    "derive_public_key_from_secret",
    "from_base64",
    "from_base64url",
    "generate_keypair",
    "to_base64",
    "to_base64url",
    "validate_keypair",
    "validate_payload",
    "validate_server_public_key",
    "verify_signature",
    "verify_signature_safe",
]
