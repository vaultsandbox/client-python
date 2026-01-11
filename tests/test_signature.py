"""Tests for signature verification module."""

from unittest.mock import patch

import pytest

from vaultsandbox.crypto.constants import MLDSA65_PUBLIC_KEY_SIZE
from vaultsandbox.crypto.signature import (
    verify_signature,
    verify_signature_safe,
)
from vaultsandbox.crypto.utils import to_base64url
from vaultsandbox.errors import SignatureVerificationError
from vaultsandbox.types import EncryptedPayload


def make_encrypted_payload(server_sig_pk_bytes: bytes) -> EncryptedPayload:
    """Create a minimal valid encrypted payload for testing."""
    return EncryptedPayload(
        v=1,
        algs={
            "kem": "ML-KEM-768",
            "sig": "ML-DSA-65",
            "aead": "AES-256-GCM",
            "kdf": "HKDF-SHA-512",
        },
        ct_kem=to_base64url(b"fake_ct_kem"),
        nonce=to_base64url(b"fake_nonce"),
        aad=to_base64url(b"fake_aad"),
        ciphertext=to_base64url(b"fake_ciphertext"),
        sig=to_base64url(b"fake_signature"),
        server_sig_pk=to_base64url(server_sig_pk_bytes),
    )


class TestVerifySignature:
    """Tests for verify_signature function."""

    def test_invalid_server_public_key_length(self) -> None:
        """Test that invalid server public key length raises SignatureVerificationError."""
        # Use a key that's too short
        invalid_pk = b"x" * 100  # Wrong size, should be MLDSA65_PUBLIC_KEY_SIZE (1952)
        payload = make_encrypted_payload(invalid_pk)

        with pytest.raises(SignatureVerificationError) as exc_info:
            verify_signature(payload)

        assert "Invalid server public key length" in str(exc_info.value)
        assert "100" in str(exc_info.value)
        assert str(MLDSA65_PUBLIC_KEY_SIZE) in str(exc_info.value)

    @patch("vaultsandbox.crypto.signature.mldsa_verify")
    def test_signature_verification_error_reraise(self, mock_verify) -> None:
        """Test that SignatureVerificationError is re-raised as-is."""
        valid_pk = b"x" * MLDSA65_PUBLIC_KEY_SIZE
        payload = make_encrypted_payload(valid_pk)

        # Make mldsa_verify raise SignatureVerificationError
        mock_verify.side_effect = SignatureVerificationError("Original error")

        with pytest.raises(SignatureVerificationError) as exc_info:
            verify_signature(payload)

        assert str(exc_info.value) == "Original error"

    @patch("vaultsandbox.crypto.signature.mldsa_verify")
    def test_value_error_wrapped(self, mock_verify) -> None:
        """Test that ValueError from mldsa_verify is wrapped in SignatureVerificationError."""
        valid_pk = b"x" * MLDSA65_PUBLIC_KEY_SIZE
        payload = make_encrypted_payload(valid_pk)

        mock_verify.side_effect = ValueError("Signature mismatch")

        with pytest.raises(SignatureVerificationError) as exc_info:
            verify_signature(payload)

        assert "SIGNATURE VERIFICATION FAILED" in str(exc_info.value)
        assert "Signature mismatch" in str(exc_info.value)

    @patch("vaultsandbox.crypto.signature.mldsa_verify")
    def test_generic_exception_wrapped(self, mock_verify) -> None:
        """Test that generic Exception is wrapped in SignatureVerificationError."""
        valid_pk = b"x" * MLDSA65_PUBLIC_KEY_SIZE
        payload = make_encrypted_payload(valid_pk)

        mock_verify.side_effect = RuntimeError("Unexpected crypto error")

        with pytest.raises(SignatureVerificationError) as exc_info:
            verify_signature(payload)

        assert "SIGNATURE VERIFICATION FAILED" in str(exc_info.value)
        assert "Unexpected crypto error" in str(exc_info.value)


class TestVerifySignatureSafe:
    """Tests for verify_signature_safe function."""

    @patch("vaultsandbox.crypto.signature.mldsa_verify")
    def test_returns_true_on_valid_signature(self, mock_verify) -> None:
        """Test that verify_signature_safe returns True when signature is valid."""
        valid_pk = b"x" * MLDSA65_PUBLIC_KEY_SIZE
        payload = make_encrypted_payload(valid_pk)

        # mldsa_verify returns None on success
        mock_verify.return_value = None

        result = verify_signature_safe(payload)

        assert result is True

    def test_returns_false_on_invalid_key(self) -> None:
        """Test that verify_signature_safe returns False for invalid public key."""
        invalid_pk = b"x" * 100
        payload = make_encrypted_payload(invalid_pk)

        result = verify_signature_safe(payload)

        assert result is False

    @patch("vaultsandbox.crypto.signature.mldsa_verify")
    def test_returns_false_on_verification_failure(self, mock_verify) -> None:
        """Test that verify_signature_safe returns False when verification fails."""
        valid_pk = b"x" * MLDSA65_PUBLIC_KEY_SIZE
        payload = make_encrypted_payload(valid_pk)

        mock_verify.side_effect = ValueError("Invalid signature")

        result = verify_signature_safe(payload)

        assert result is False
