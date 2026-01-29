# Changelog

All notable changes to this project will be documented in this file.

The format is inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.9.2] - 2026-01-29

### Changed

- Tests now run in parallel with pytest-xdist (~3x faster)
- Replaced time-based sleeps with event-based synchronization in tests

## [0.9.1] - 2026-01-26

### Changed

- Refactored ApiClient into domain-specific classes
- Improved parameter validation and error messages
- Fixed SSE race conditions and timestamp error handling
- Fixed base64 error handling
- Added webhook URL validation

### Fixed

- Fixed HTTP client leak during SSE reconnection
- Fixed unhandled UnicodeDecodeError in webhook signature verification
- Improved error handling during SSE unsubscribe sync

## [0.9.0] - 2026-01-22

### Added

- Chaos Engineering

## [0.8.5] - 2026-01-19

### Added

- Spam analysis support (Rspamd integration)
- Inbox creation option to enable/disable spam analysis
- Server capability detection for spam analysis

## [0.8.0] - 2026-01-16

### Added

- Webhooks support for inbox

## [0.7.0] - 2026-01-13

### Added

- Optional encryption support with `encryptionPolicy` option
- Optional email authentication feature

### Changed

- Updated ReverseDNS structure
- License changed from MIT to Apache 2.0

## [0.6.1] - 2026-01-11

### Changed

- Default delivery strategy changed from `AUTO` to `SSE`
- SSE strategy now syncs subscriptions after reconnect to catch emails during disconnect window

### Removed

- `DeliveryStrategyType.AUTO` enum value (use `SSE` or `POLLING` explicitly)

## [0.6.0] - 2026-01-04

### Added

- `list_emails_metadata_only()` method for efficient metadata-only email listing
- `EmailMetadata` type with `id`, `from_address`, `subject`, `received_at`, `is_read` fields
- `include_content` parameter to API client's `list_emails()` method
- New error types for granular cryptographic validation:
  - `UnsupportedVersionError` - Protocol or export version not supported
  - `InvalidPayloadError` - Malformed JSON or missing required fields
  - `InvalidAlgorithmError` - Unrecognized or unsupported algorithm
  - `InvalidSizeError` - Decoded field has incorrect size
  - `ServerKeyMismatchError` - Server public key doesn't match pinned key
- Encrypted payload validation before decryption (structure, version, algorithms, sizes)
- Server key pinning support to detect server key mismatches
- `delete_inbox()` method to delete a specific inbox by email address
- `Base64URLDecodeError` for strict Base64URL validation
- Additional crypto constants: `ALGORITHM_SUITE`, `PROTOCOL_VERSION`, `EXPORT_VERSION`, `MLKEM768_CIPHERTEXT_SIZE`, `MLKEM768_SHARED_SECRET_SIZE`, `MLDSA65_SIGNATURE_SIZE`
- New `validation` module in crypto package for payload validation

### Changed

- `list_emails()` now fetches full content in single request (removes N+1 query pattern)
- Export format now includes `version` field and uses `secretKey` instead of `secretKeyB64`/`publicKeyB64` (public key is derived from secret key)
- Base64URL decoding now strictly rejects `+`, `/`, and `=` characters per spec
- Decryption functions now accept optional `pinned_server_key` parameter
- Generic error messages during decryption failures to prevent oracle attacks

### Removed

- `public_key_b64` field from `ExportedInbox` (public key derived from secret key)

## [0.5.1] - 2026-01-01

### Changed

- Standardized email authentication result structs to match wire format and other SDKs

### Added

- End-to-end integration tests for email authentication results using the test email API

### Removed

- `ReverseDNSStatus` enum (no longer needed)

## [0.5.0] - 2025-12-17

### Initial release

- Quantum-safe email testing SDK with ML-KEM-768 encryption
- Automatic keypair generation and management
- Support for both polling and real-time (SSE) email delivery
- Full email content access including attachments and headers
- Built-in SPF/DKIM/DMARC authentication validation
- Full type hints with `py.typed` marker for IDE support
- Inbox import/export functionality for test reproducibility
- Comprehensive error handling with automatic retries
