"""Tests for crypto/decrypt.py module."""

from __future__ import annotations

import base64
import json
import sys
from typing import Any
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqcrypto.kem.ml_kem_768 import encrypt as mlkem_encapsulate
from pqcrypto.sign.ml_dsa_65 import generate_keypair as mldsa_generate_keypair
from pqcrypto.sign.ml_dsa_65 import sign as mldsa_sign

from vaultsandbox.crypto import generate_keypair, to_base64url
from vaultsandbox.crypto.constants import (
    AES_GCM_NONCE_SIZE,
    EXPECTED_AEAD,
    EXPECTED_KDF,
    EXPECTED_KEM,
    EXPECTED_SIG,
    HKDF_CONTEXT,
)
from vaultsandbox.crypto.decrypt import (
    decrypt,
    decrypt_json,
    decrypt_metadata,
    decrypt_parsed,
    decrypt_raw,
)
from vaultsandbox.crypto.keypair import derive_key
from vaultsandbox.errors import (
    DecryptionError,
    InvalidAlgorithmError,
    InvalidPayloadError,
    InvalidSizeError,
    ServerKeyMismatchError,
    SignatureVerificationError,
    UnsupportedVersionError,
)
from vaultsandbox.types import EncryptedPayload


def create_valid_payload(
    plaintext: bytes,
    recipient_public_key: bytes,
    server_signing_keypair: tuple[bytes, bytes] | None = None,
) -> tuple[EncryptedPayload, tuple[bytes, bytes]]:
    """Create a valid encrypted payload for testing.

    Args:
        plaintext: The plaintext to encrypt.
        recipient_public_key: The recipient's ML-KEM-768 public key.
        server_signing_keypair: Optional (public_key, secret_key) for signing.

    Returns:
        Tuple of (EncryptedPayload, server_signing_keypair).
    """
    import os

    # Generate server signing keypair if not provided
    if server_signing_keypair is None:
        server_sig_pk, server_sig_sk = mldsa_generate_keypair()
        server_signing_keypair = (bytes(server_sig_pk), bytes(server_sig_sk))
    else:
        server_sig_pk, server_sig_sk = server_signing_keypair

    # Encapsulate to get shared secret and ciphertext
    ciphertext_kem, shared_secret = mlkem_encapsulate(recipient_public_key)

    # Generate nonce and AAD
    nonce = os.urandom(AES_GCM_NONCE_SIZE)
    aad = os.urandom(32)  # Example AAD

    # Derive AES key
    aes_key = derive_key(bytes(shared_secret), bytes(ciphertext_kem), aad)

    # Encrypt with AES-256-GCM
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    # Build the payload structure
    payload: dict[str, Any] = {
        "v": 1,
        "algs": {
            "kem": EXPECTED_KEM,
            "sig": EXPECTED_SIG,
            "aead": EXPECTED_AEAD,
            "kdf": EXPECTED_KDF,
        },
        "ct_kem": to_base64url(ciphertext_kem),
        "nonce": to_base64url(nonce),
        "aad": to_base64url(aad),
        "ciphertext": to_base64url(ciphertext),
        "server_sig_pk": to_base64url(server_sig_pk),
        "sig": "",  # Placeholder, will be computed
    }

    # Build transcript for signing
    version_bytes = bytes([payload["v"]])
    algs = payload["algs"]
    algs_ciphersuite = f"{algs['kem']}:{algs['sig']}:{algs['aead']}:{algs['kdf']}"
    algs_bytes = algs_ciphersuite.encode("utf-8")
    context_bytes = HKDF_CONTEXT.encode("utf-8")

    transcript = (
        version_bytes
        + algs_bytes
        + context_bytes
        + bytes(ciphertext_kem)
        + nonce
        + aad
        + ciphertext
        + bytes(server_sig_pk)
    )

    # Sign the transcript
    signature = mldsa_sign(server_sig_sk, transcript)
    payload["sig"] = to_base64url(signature)

    return payload, server_signing_keypair


class TestDecrypt:
    """Tests for the decrypt() function."""

    def test_decrypt_success(self) -> None:
        """Test successful decryption of valid payload."""
        keypair = generate_keypair()
        plaintext = b"Hello, VaultSandbox!"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        result = decrypt(payload, keypair)

        assert result == plaintext

    def test_decrypt_with_pinned_server_key(self) -> None:
        """Test decryption with pinned server key validation."""
        keypair = generate_keypair()
        plaintext = b"Test with pinned key"

        payload, (server_sig_pk, _) = create_valid_payload(plaintext, keypair.public_key)
        pinned_key = to_base64url(server_sig_pk)

        result = decrypt(payload, keypair, pinned_server_key=pinned_key)
        assert result == plaintext

    def test_decrypt_server_key_mismatch(self) -> None:
        """Test that server key mismatch raises ServerKeyMismatchError."""
        keypair = generate_keypair()
        plaintext = b"Test server key mismatch"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)

        # Use a different pinned key
        different_pk, _ = mldsa_generate_keypair()
        wrong_pinned_key = to_base64url(different_pk)

        with pytest.raises(ServerKeyMismatchError):
            decrypt(payload, keypair, pinned_server_key=wrong_pinned_key)

    def test_decrypt_missing_field_raises_invalid_payload(self) -> None:
        """Test that missing required field raises InvalidPayloadError."""
        keypair = generate_keypair()
        plaintext = b"Test missing field"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        del payload["ct_kem"]

        with pytest.raises(InvalidPayloadError, match="Missing required field"):
            decrypt(payload, keypair)

    def test_decrypt_wrong_version_raises_unsupported_version(self) -> None:
        """Test that wrong protocol version raises UnsupportedVersionError."""
        keypair = generate_keypair()
        plaintext = b"Test wrong version"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        payload["v"] = 2

        with pytest.raises(UnsupportedVersionError, match="Unsupported protocol version"):
            decrypt(payload, keypair)

    def test_decrypt_wrong_kem_algorithm_raises_invalid_algorithm(self) -> None:
        """Test that wrong KEM algorithm raises InvalidAlgorithmError."""
        keypair = generate_keypair()
        plaintext = b"Test wrong KEM"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        payload["algs"]["kem"] = "WRONG-KEM"

        with pytest.raises(InvalidAlgorithmError, match="Unsupported KEM algorithm"):
            decrypt(payload, keypair)

    def test_decrypt_wrong_sig_algorithm_raises_invalid_algorithm(self) -> None:
        """Test that wrong signature algorithm raises InvalidAlgorithmError."""
        keypair = generate_keypair()
        plaintext = b"Test wrong sig"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        payload["algs"]["sig"] = "WRONG-SIG"

        with pytest.raises(InvalidAlgorithmError, match="Unsupported signature algorithm"):
            decrypt(payload, keypair)

    def test_decrypt_wrong_aead_algorithm_raises_invalid_algorithm(self) -> None:
        """Test that wrong AEAD algorithm raises InvalidAlgorithmError."""
        keypair = generate_keypair()
        plaintext = b"Test wrong aead"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        payload["algs"]["aead"] = "WRONG-AEAD"

        with pytest.raises(InvalidAlgorithmError, match="Unsupported AEAD algorithm"):
            decrypt(payload, keypair)

    def test_decrypt_wrong_kdf_algorithm_raises_invalid_algorithm(self) -> None:
        """Test that wrong KDF algorithm raises InvalidAlgorithmError."""
        keypair = generate_keypair()
        plaintext = b"Test wrong kdf"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        payload["algs"]["kdf"] = "WRONG-KDF"

        with pytest.raises(InvalidAlgorithmError, match="Unsupported KDF algorithm"):
            decrypt(payload, keypair)

    def test_decrypt_invalid_ct_kem_size_raises_invalid_size(self) -> None:
        """Test that invalid ct_kem size raises InvalidSizeError."""
        keypair = generate_keypair()
        plaintext = b"Test invalid ct_kem size"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        payload["ct_kem"] = to_base64url(b"too short")

        with pytest.raises(InvalidSizeError, match="Invalid ct_kem size"):
            decrypt(payload, keypair)

    def test_decrypt_invalid_nonce_size_raises_invalid_size(self) -> None:
        """Test that invalid nonce size raises InvalidSizeError."""
        keypair = generate_keypair()
        plaintext = b"Test invalid nonce size"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        payload["nonce"] = to_base64url(b"short")

        with pytest.raises(InvalidSizeError, match="Invalid nonce size"):
            decrypt(payload, keypair)

    def test_decrypt_invalid_signature_size_raises_invalid_size(self) -> None:
        """Test that invalid signature size raises InvalidSizeError."""
        keypair = generate_keypair()
        plaintext = b"Test invalid sig size"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        payload["sig"] = to_base64url(b"invalid signature")

        with pytest.raises(InvalidSizeError, match="Invalid signature size"):
            decrypt(payload, keypair)

    def test_decrypt_invalid_server_pk_size_raises_invalid_size(self) -> None:
        """Test that invalid server_sig_pk size raises InvalidSizeError."""
        keypair = generate_keypair()
        plaintext = b"Test invalid server pk size"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        payload["server_sig_pk"] = to_base64url(b"invalid pk")

        with pytest.raises(InvalidSizeError, match="Invalid server_sig_pk size"):
            decrypt(payload, keypair)

    def test_decrypt_signature_verification_error_propagates(self) -> None:
        """Test that SignatureVerificationError from verify_signature propagates."""
        keypair = generate_keypair()
        plaintext = b"Test signature error"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)

        decrypt_module = sys.modules["vaultsandbox.crypto.decrypt"]
        with (
            patch.object(
                decrypt_module,
                "verify_signature",
                side_effect=SignatureVerificationError("Signature verification failed"),
            ),
            pytest.raises(SignatureVerificationError),
        ):
            decrypt(payload, keypair)

    def test_decrypt_tampered_ciphertext_fails_aes_decryption(self) -> None:
        """Test that tampered ciphertext fails at AES decryption."""
        keypair = generate_keypair()
        plaintext = b"Test tampered ciphertext"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)

        # Tamper with ciphertext - AES-GCM will detect tampering via auth tag
        from vaultsandbox.crypto.utils import from_base64url

        original_ct = from_base64url(payload["ciphertext"])
        # Flip a bit in the ciphertext
        tampered = bytearray(original_ct)
        tampered[0] ^= 0xFF
        payload["ciphertext"] = to_base64url(bytes(tampered))

        # This will fail at AES decryption due to auth tag mismatch
        with pytest.raises(DecryptionError):
            decrypt(payload, keypair)

    def test_decrypt_wrong_keypair_raises_decryption_error(self) -> None:
        """Test that wrong keypair raises DecryptionError."""
        keypair = generate_keypair()
        wrong_keypair = generate_keypair()
        plaintext = b"Test wrong keypair"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)

        with pytest.raises(DecryptionError):
            decrypt(payload, wrong_keypair)

    def test_decrypt_generic_exception_wrapped_as_decryption_error(self) -> None:
        """Test that generic exceptions are wrapped as DecryptionError."""
        keypair = generate_keypair()
        plaintext = b"Test generic exception"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)

        decrypt_module = sys.modules["vaultsandbox.crypto.decrypt"]
        with (
            patch.object(
                decrypt_module,
                "mlkem_decapsulate",
                side_effect=RuntimeError("Unexpected error"),
            ),
            pytest.raises(DecryptionError, match="Decryption failed"),
        ):
            decrypt(payload, keypair)

    def test_decrypt_decryption_error_passthrough(self) -> None:
        """Test that DecryptionError from internal operations is re-raised as-is."""
        keypair = generate_keypair()
        plaintext = b"Test decryption error passthrough"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)

        # Mock derive_key to raise DecryptionError directly
        decrypt_module = sys.modules["vaultsandbox.crypto.decrypt"]
        with (
            patch.object(
                decrypt_module,
                "derive_key",
                side_effect=DecryptionError("Key derivation failed"),
            ),
            pytest.raises(DecryptionError, match="Key derivation failed"),
        ):
            decrypt(payload, keypair)


class TestDecryptJson:
    """Tests for the decrypt_json() function."""

    def test_decrypt_json_success(self) -> None:
        """Test successful JSON decryption."""
        keypair = generate_keypair()
        data = {"key": "value", "number": 42}
        plaintext = json.dumps(data).encode("utf-8")

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        result = decrypt_json(payload, keypair)

        assert result == data

    def test_decrypt_json_with_context(self) -> None:
        """Test JSON decryption with custom context for error messages."""
        keypair = generate_keypair()
        data = {"test": "data"}
        plaintext = json.dumps(data).encode("utf-8")

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        result = decrypt_json(payload, keypair, context="test_context")

        assert result == data

    def test_decrypt_json_with_pinned_server_key(self) -> None:
        """Test JSON decryption with pinned server key."""
        keypair = generate_keypair()
        data = {"secure": True}
        plaintext = json.dumps(data).encode("utf-8")

        payload, (server_sig_pk, _) = create_valid_payload(plaintext, keypair.public_key)
        pinned_key = to_base64url(server_sig_pk)

        result = decrypt_json(payload, keypair, pinned_server_key=pinned_key)
        assert result == data

    def test_decrypt_json_invalid_json_raises_decryption_error(self) -> None:
        """Test that invalid JSON raises DecryptionError."""
        keypair = generate_keypair()
        plaintext = b"not valid json {{"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)

        with pytest.raises(DecryptionError, match="Failed to parse decrypted"):
            decrypt_json(payload, keypair)

    def test_decrypt_json_propagates_validation_errors(self) -> None:
        """Test that validation errors are propagated."""
        keypair = generate_keypair()
        plaintext = json.dumps({"test": 1}).encode("utf-8")

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        payload["v"] = 99  # Invalid version

        with pytest.raises(UnsupportedVersionError):
            decrypt_json(payload, keypair)

    def test_decrypt_json_propagates_signature_error(self) -> None:
        """Test that signature errors are propagated."""
        keypair = generate_keypair()
        plaintext = json.dumps({"test": 1}).encode("utf-8")

        payload, _ = create_valid_payload(plaintext, keypair.public_key)

        decrypt_module = sys.modules["vaultsandbox.crypto.decrypt"]
        with (
            patch.object(
                decrypt_module,
                "verify_signature",
                side_effect=SignatureVerificationError("Signature verification failed"),
            ),
            pytest.raises(SignatureVerificationError),
        ):
            decrypt_json(payload, keypair)


class TestDecryptMetadata:
    """Tests for the decrypt_metadata() function."""

    def test_decrypt_metadata_success(self) -> None:
        """Test successful metadata decryption."""
        keypair = generate_keypair()
        metadata = {
            "from": "sender@example.com",
            "to": ["recipient@example.com"],
            "subject": "Test Subject",
        }
        plaintext = json.dumps(metadata).encode("utf-8")

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        result = decrypt_metadata(payload, keypair)

        assert result == metadata

    def test_decrypt_metadata_with_pinned_key(self) -> None:
        """Test metadata decryption with pinned server key."""
        keypair = generate_keypair()
        metadata = {"subject": "Secure metadata"}
        plaintext = json.dumps(metadata).encode("utf-8")

        payload, (server_sig_pk, _) = create_valid_payload(plaintext, keypair.public_key)
        pinned_key = to_base64url(server_sig_pk)

        result = decrypt_metadata(payload, keypair, pinned_server_key=pinned_key)
        assert result == metadata

    def test_decrypt_metadata_invalid_json(self) -> None:
        """Test that invalid JSON metadata raises DecryptionError."""
        keypair = generate_keypair()
        plaintext = b"invalid json"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)

        with pytest.raises(DecryptionError, match="metadata"):
            decrypt_metadata(payload, keypair)


class TestDecryptParsed:
    """Tests for the decrypt_parsed() function."""

    def test_decrypt_parsed_success(self) -> None:
        """Test successful parsed content decryption."""
        keypair = generate_keypair()
        content = {
            "text": "Hello, this is the email body",
            "html": "<p>Hello</p>",
        }
        plaintext = json.dumps(content).encode("utf-8")

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        result = decrypt_parsed(payload, keypair)

        assert result == content

    def test_decrypt_parsed_with_pinned_key(self) -> None:
        """Test parsed decryption with pinned server key."""
        keypair = generate_keypair()
        content = {"body": "Test content"}
        plaintext = json.dumps(content).encode("utf-8")

        payload, (server_sig_pk, _) = create_valid_payload(plaintext, keypair.public_key)
        pinned_key = to_base64url(server_sig_pk)

        result = decrypt_parsed(payload, keypair, pinned_server_key=pinned_key)
        assert result == content

    def test_decrypt_parsed_invalid_json(self) -> None:
        """Test that invalid JSON content raises DecryptionError."""
        keypair = generate_keypair()
        plaintext = b"not json"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)

        with pytest.raises(DecryptionError, match="content"):
            decrypt_parsed(payload, keypair)


class TestDecryptRaw:
    """Tests for the decrypt_raw() function."""

    def test_decrypt_raw_success(self) -> None:
        """Test successful raw email decryption."""
        keypair = generate_keypair()
        raw_email = "From: sender@example.com\r\nTo: recipient@example.com\r\n\r\nBody"
        # Raw email is base64 encoded in the encrypted payload
        plaintext = base64.b64encode(raw_email.encode("utf-8"))

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        result = decrypt_raw(payload, keypair)

        assert result == raw_email

    def test_decrypt_raw_with_pinned_key(self) -> None:
        """Test raw decryption with pinned server key."""
        keypair = generate_keypair()
        raw_email = "Subject: Test\r\n\r\nBody"
        plaintext = base64.b64encode(raw_email.encode("utf-8"))

        payload, (server_sig_pk, _) = create_valid_payload(plaintext, keypair.public_key)
        pinned_key = to_base64url(server_sig_pk)

        result = decrypt_raw(payload, keypair, pinned_server_key=pinned_key)
        assert result == raw_email

    def test_decrypt_raw_invalid_base64_raises_decryption_error(self) -> None:
        """Test that invalid base64 in raw content raises DecryptionError."""
        keypair = generate_keypair()
        plaintext = b"not valid base64!!!"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)

        with pytest.raises(DecryptionError, match="Failed to decode"):
            decrypt_raw(payload, keypair)

    def test_decrypt_raw_invalid_utf8_raises_decryption_error(self) -> None:
        """Test that invalid UTF-8 in decoded raw raises DecryptionError."""
        keypair = generate_keypair()
        # Create valid base64 that decodes to invalid UTF-8
        invalid_utf8 = b"\xff\xfe"
        plaintext = base64.b64encode(invalid_utf8)

        payload, _ = create_valid_payload(plaintext, keypair.public_key)

        with pytest.raises(DecryptionError, match="Failed to decode"):
            decrypt_raw(payload, keypair)

    def test_decrypt_raw_propagates_validation_errors(self) -> None:
        """Test that validation errors are propagated."""
        keypair = generate_keypair()
        raw_email = "Test"
        plaintext = base64.b64encode(raw_email.encode("utf-8"))

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        del payload["nonce"]  # Remove required field

        with pytest.raises(InvalidPayloadError):
            decrypt_raw(payload, keypair)


class TestDecryptEdgeCases:
    """Edge case tests for decrypt functions."""

    def test_decrypt_empty_plaintext(self) -> None:
        """Test decryption of empty plaintext."""
        keypair = generate_keypair()
        plaintext = b""

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        result = decrypt(payload, keypair)

        assert result == b""

    def test_decrypt_large_plaintext(self) -> None:
        """Test decryption of large plaintext."""
        keypair = generate_keypair()
        plaintext = b"x" * 100000  # 100KB

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        result = decrypt(payload, keypair)

        assert result == plaintext

    def test_decrypt_binary_plaintext(self) -> None:
        """Test decryption of binary plaintext."""
        keypair = generate_keypair()
        plaintext = bytes(range(256))  # All byte values

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        result = decrypt(payload, keypair)

        assert result == plaintext

    def test_decrypt_unicode_json(self) -> None:
        """Test decryption of JSON with unicode characters."""
        keypair = generate_keypair()
        data = {"message": "Hello, 世界! 🌍"}
        plaintext = json.dumps(data).encode("utf-8")

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        result = decrypt_json(payload, keypair)

        assert result == data

    def test_decrypt_reuse_server_keypair(self) -> None:
        """Test that multiple payloads can use the same server keypair."""
        keypair = generate_keypair()
        server_sig_pk, server_sig_sk = mldsa_generate_keypair()
        server_keypair = (bytes(server_sig_pk), bytes(server_sig_sk))

        # Encrypt two different plaintexts with same server key
        plaintext1 = b"First message"
        plaintext2 = b"Second message"

        payload1, _ = create_valid_payload(
            plaintext1, keypair.public_key, server_signing_keypair=server_keypair
        )
        payload2, _ = create_valid_payload(
            plaintext2, keypair.public_key, server_signing_keypair=server_keypair
        )

        pinned_key = to_base64url(server_sig_pk)

        result1 = decrypt(payload1, keypair, pinned_server_key=pinned_key)
        result2 = decrypt(payload2, keypair, pinned_server_key=pinned_key)

        assert result1 == plaintext1
        assert result2 == plaintext2


class TestDecryptPayloadValidation:
    """Tests for payload structure validation."""

    def test_missing_algs_field(self) -> None:
        """Test that missing algs field raises InvalidPayloadError."""
        keypair = generate_keypair()
        plaintext = b"test"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        del payload["algs"]

        with pytest.raises(InvalidPayloadError, match="Missing required field"):
            decrypt(payload, keypair)

    def test_invalid_algs_type(self) -> None:
        """Test that non-object algs raises InvalidPayloadError."""
        keypair = generate_keypair()
        plaintext = b"test"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        payload["algs"] = "not an object"

        with pytest.raises(InvalidPayloadError, match="algs.*must be an object"):
            decrypt(payload, keypair)

    def test_missing_alg_subfield(self) -> None:
        """Test that missing algorithm subfield raises InvalidPayloadError."""
        keypair = generate_keypair()
        plaintext = b"test"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        del payload["algs"]["kdf"]

        with pytest.raises(InvalidPayloadError, match="Missing required field.*algs.kdf"):
            decrypt(payload, keypair)

    def test_invalid_ct_kem_encoding(self) -> None:
        """Test that invalid base64 in ct_kem raises InvalidPayloadError."""
        keypair = generate_keypair()
        plaintext = b"test"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        payload["ct_kem"] = "!!!not-valid-base64!!!"

        with pytest.raises(InvalidPayloadError, match="Failed to decode ct_kem"):
            decrypt(payload, keypair)

    def test_invalid_nonce_encoding(self) -> None:
        """Test that invalid base64 in nonce raises InvalidPayloadError."""
        keypair = generate_keypair()
        plaintext = b"test"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        payload["nonce"] = "!!!not-valid-base64!!!"

        with pytest.raises(InvalidPayloadError, match="Failed to decode nonce"):
            decrypt(payload, keypair)

    def test_invalid_sig_encoding(self) -> None:
        """Test that invalid base64 in sig raises InvalidPayloadError."""
        keypair = generate_keypair()
        plaintext = b"test"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        payload["sig"] = "!!!not-valid-base64!!!"

        with pytest.raises(InvalidPayloadError, match="Failed to decode sig"):
            decrypt(payload, keypair)

    def test_invalid_server_sig_pk_encoding(self) -> None:
        """Test that invalid base64 in server_sig_pk raises InvalidPayloadError."""
        keypair = generate_keypair()
        plaintext = b"test"

        payload, _ = create_valid_payload(plaintext, keypair.public_key)
        payload["server_sig_pk"] = "!!!not-valid-base64!!!"

        with pytest.raises(InvalidPayloadError, match="Failed to decode server_sig_pk"):
            decrypt(payload, keypair)
