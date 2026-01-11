"""Tests for crypto module."""

import pytest

from vaultsandbox.crypto import (
    Keypair,
    derive_public_key_from_secret,
    from_base64url,
    generate_keypair,
    to_base64url,
    validate_keypair,
)
from vaultsandbox.crypto.constants import (
    MLKEM768_PUBLIC_KEY_SIZE,
    MLKEM768_SECRET_KEY_SIZE,
)
from vaultsandbox.crypto.utils import (
    Base64URLDecodeError,
    from_base64,
    to_base64,
)


class TestBase64Url:
    """Tests for base64url encoding/decoding."""

    def test_round_trip(self) -> None:
        """Test that encoding and decoding produces original data."""
        data = b"Hello, World!"
        encoded = to_base64url(data)
        decoded = from_base64url(encoded)
        assert decoded == data

    def test_no_padding(self) -> None:
        """Test that encoding produces no padding characters."""
        data = b"test"
        encoded = to_base64url(data)
        assert "=" not in encoded

    def test_url_safe_chars(self) -> None:
        """Test that encoding uses URL-safe characters."""
        # Data that would produce + and / in standard base64
        data = b"\xfb\xff\xfe"
        encoded = to_base64url(data)
        assert "+" not in encoded
        assert "/" not in encoded

    def test_decode_rejects_plus(self) -> None:
        """Test that decoding rejects + character."""
        with pytest.raises(Base64URLDecodeError, match="contains forbidden characters"):
            from_base64url("abc+def")

    def test_decode_rejects_slash(self) -> None:
        """Test that decoding rejects / character."""
        with pytest.raises(Base64URLDecodeError, match="contains forbidden characters"):
            from_base64url("abc/def")

    def test_decode_rejects_padding(self) -> None:
        """Test that decoding rejects = padding."""
        with pytest.raises(Base64URLDecodeError, match="contains forbidden characters"):
            from_base64url("abc=")

    def test_decode_rejects_invalid_chars(self) -> None:
        """Test that decoding rejects other invalid characters."""
        with pytest.raises(Base64URLDecodeError, match="contains non-Base64URL characters"):
            from_base64url("abc!def")


class TestBase64:
    """Tests for standard base64 encoding/decoding."""

    def test_to_base64(self) -> None:
        """Test standard base64 encoding."""
        data = b"Hello, World!"
        encoded = to_base64(data)
        assert encoded == "SGVsbG8sIFdvcmxkIQ=="

    def test_from_base64(self) -> None:
        """Test standard base64 decoding."""
        encoded = "SGVsbG8sIFdvcmxkIQ=="
        decoded = from_base64(encoded)
        assert decoded == b"Hello, World!"


class TestKeypair:
    """Tests for keypair generation and validation."""

    def test_generate_keypair(self) -> None:
        """Test keypair generation produces valid keys."""
        keypair = generate_keypair()
        assert len(keypair.public_key) == MLKEM768_PUBLIC_KEY_SIZE
        assert len(keypair.secret_key) == MLKEM768_SECRET_KEY_SIZE
        assert keypair.public_key_b64 == to_base64url(keypair.public_key)

    def test_validate_keypair(self) -> None:
        """Test keypair validation."""
        keypair = generate_keypair()
        assert validate_keypair(keypair) is True

    def test_derive_public_key_from_secret(self) -> None:
        """Test deriving public key from secret key."""
        keypair = generate_keypair()
        derived = derive_public_key_from_secret(keypair.secret_key)
        assert derived == keypair.public_key

    def test_derive_public_key_invalid_length(self) -> None:
        """Test that invalid secret key length raises error."""
        with pytest.raises(ValueError, match="Invalid secret key length"):
            derive_public_key_from_secret(b"too short")

    def test_unique_keypairs(self) -> None:
        """Generate two keypairs and verify they are different."""
        kp1 = generate_keypair()
        kp2 = generate_keypair()
        assert kp1.public_key != kp2.public_key
        assert kp1.secret_key != kp2.secret_key

    def test_correct_key_sizes(self) -> None:
        """Check ML-KEM-768 key sizes are correct."""
        kp = generate_keypair()
        assert len(kp.public_key) == MLKEM768_PUBLIC_KEY_SIZE  # 1184 bytes
        assert len(kp.secret_key) == MLKEM768_SECRET_KEY_SIZE  # 2400 bytes

    def test_validate_keypair_invalid_public_key_size(self) -> None:
        """Validate keypair with wrong public key size returns false."""
        kp = generate_keypair()
        # Create invalid keypair with wrong public key size
        invalid_kp = Keypair(
            public_key=b"short",
            secret_key=kp.secret_key,
            public_key_b64=to_base64url(b"short"),
        )
        assert validate_keypair(invalid_kp) is False

    def test_validate_keypair_invalid_secret_key_size(self) -> None:
        """Validate keypair with wrong secret key size returns false."""
        kp = generate_keypair()
        # Create invalid keypair with wrong secret key size
        invalid_kp = Keypair(
            public_key=kp.public_key,
            secret_key=b"short",
            public_key_b64=kp.public_key_b64,
        )
        assert validate_keypair(invalid_kp) is False
