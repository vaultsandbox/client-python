"""Cryptographic constants for VaultSandbox SDK.

These constants follow the VaultSandbox Cryptographic Protocol Specification.
See Appendix B: Size Constants for reference.
"""

# Context string for HKDF key derivation (Section 6.3)
HKDF_CONTEXT = "vaultsandbox:email:v1"

# Algorithm suite identifier (Section 3.1)
ALGORITHM_SUITE = "ML-KEM-768:ML-DSA-65:AES-256-GCM:HKDF-SHA-512"

# Protocol version (Section 5.2)
PROTOCOL_VERSION = 1

# Export format version (Section 9.3)
EXPORT_VERSION = 1

# ML-KEM-768 sizes (Section 3.2, Appendix B)
MLKEM768_PUBLIC_KEY_SIZE = 1184  # Public key size in bytes
MLKEM768_SECRET_KEY_SIZE = 2400  # Secret key size in bytes
MLKEM768_CIPHERTEXT_SIZE = 1088  # Ciphertext size in bytes
MLKEM768_SHARED_SECRET_SIZE = 32  # Shared secret size in bytes
MLKEM768_PUBLIC_KEY_OFFSET = 1152  # Offset of public key within secret key
# CPA private key size: 12 * k * n / 8 where k=3, n=256
MLKEM768_CPA_PRIVATE_KEY_SIZE = 1152

# ML-DSA-65 sizes (Section 3.3, Appendix B)
MLDSA65_PUBLIC_KEY_SIZE = 1952  # Public key size in bytes
MLDSA65_SIGNATURE_SIZE = 3309  # Signature size in bytes

# AES-256-GCM sizes (Section 3.4, Appendix B)
AES_KEY_SIZE = 32  # Key size in bytes (256 bits)
AES_GCM_NONCE_SIZE = 12  # Nonce size in bytes (96 bits)
AES_GCM_TAG_SIZE = 16  # Authentication tag size in bytes (128 bits)

# Expected algorithm identifiers (Section 5.2)
EXPECTED_KEM = "ML-KEM-768"
EXPECTED_SIG = "ML-DSA-65"
EXPECTED_AEAD = "AES-256-GCM"
EXPECTED_KDF = "HKDF-SHA-512"
