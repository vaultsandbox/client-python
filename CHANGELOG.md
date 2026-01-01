# Changelog

All notable changes to this project will be documented in this file.

The format is inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
