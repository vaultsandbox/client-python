"""Cryptographic constants for VaultSandbox SDK."""

# Context string for HKDF key derivation
HKDF_CONTEXT = "vaultsandbox:email:v1"

# ML-DSA-65 (Dilithium3) public key size in bytes
MLDSA65_PUBLIC_KEY_SIZE = 1952

# ML-KEM-768 key sizes
MLKEM768_PUBLIC_KEY_SIZE = 1184
MLKEM768_SECRET_KEY_SIZE = 2400
# CPA private key size: 12 * k * n / 8 where k=3, n=256
MLKEM768_CPA_PRIVATE_KEY_SIZE = 1152

# AES-256-GCM constants
AES_KEY_SIZE = 32
AES_GCM_NONCE_SIZE = 12
AES_GCM_TAG_SIZE = 16
