# Changelog

All notable changes to this project will be documented in this file.

The format is inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.5.1] - 2026-01-01

### Changed

- **Breaking:** Renamed `status` field to `result` on `SPFResult`, `DKIMResult`, and `DMARCResult` to match wire format
- **Breaking:** Renamed `info` field to `details` on `SPFResult`
- **Breaking:** Renamed `info` field to `signature` on `DKIMResult`
- **Breaking:** Replaced `status: ReverseDNSStatus` with `verified: bool` on `ReverseDNSResult`
- Removed `info` field from `DMARCResult`

### Added

- Tests for parsing auth results from wire format (`TestAuthResultsParsing`)
- Comprehensive email auth tests using Test Email API (`test_email_auth.py`) covering all SPF, DKIM, DMARC, and Reverse DNS scenarios

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
