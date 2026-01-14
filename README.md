<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="./assets/logo-light.svg">
  <img alt="VaultSandbox" src="./assets/logo-dark.svg">
</picture>

> **VaultSandbox is in Public Beta.** Join the journey to 1.0. Share feedback on [GitHub](https://github.com/vaultsandbox/gateway/discussions).

# @vaultsandbox/client-python

[![PyPI version](https://img.shields.io/pypi/v/vaultsandbox.svg)](https://pypi.org/project/vaultsandbox/)
[![CI](https://github.com/vaultsandbox/client-python/actions/workflows/ci.yml/badge.svg)](https://github.com/vaultsandbox/client-python/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/python-%3E%3D3.10-brightgreen.svg)](https://www.python.org/)

**Production-like email testing. Self-hosted & secure.**

The official Python SDK for [VaultSandbox Gateway](https://github.com/vaultsandbox/gateway) — a secure, receive-only SMTP server for QA/testing environments. This SDK abstracts quantum-safe encryption complexity, making email testing workflows transparent and effortless.

Stop mocking your email stack. If your app sends real emails in production, it must send real emails in testing. VaultSandbox provides isolated inboxes that behave exactly like production without exposing a single byte of customer data.

> **Python 3.10+** required.

## Why VaultSandbox?

| Feature             | Simple Mocks     | Public SaaS  | **VaultSandbox**    |
| :------------------ | :--------------- | :----------- | :------------------ |
| **TLS/SSL**         | Ignored/Disabled | Partial      | **Real ACME certs** |
| **Data Privacy**    | Local only       | Shared cloud | **Private VPC**     |
| **Inbound Mail**    | Outbound only    | Yes          | **Real MX**         |
| **Auth (SPF/DKIM)** | None             | Limited      | **Full Validation** |
| **Crypto**          | Plaintext        | Varies       | **Zero-Knowledge**  |

## Features

- **Quantum-Safe Encryption** — Automatic ML-KEM-768 (Kyber768) key encapsulation + AES-256-GCM encryption
- **Zero Crypto Knowledge Required** — All cryptographic operations are invisible to the user
- **Real-Time Email Delivery** — SSE-based delivery with polling alternative
- **Built for CI/CD** — Deterministic tests without sleeps, polling, or flakiness
- **Full Email Access** — Decrypt and access email content, headers, links, and attachments
- **Email Authentication** — Built-in SPF/DKIM/DMARC validation helpers
- **Type-Safe** — Full type hints with `py.typed` marker for IDE support

## Installation

```bash
pip install vaultsandbox
```

## Quick Start

```python
import asyncio
from vaultsandbox import VaultSandboxClient

async def main():
    async with VaultSandboxClient(api_key="your-api-key") as client:
        # Create a temporary inbox
        inbox = await client.create_inbox()
        print(f"Send emails to: {inbox.email_address}")

        # Wait for an email (with 30 second timeout)
        email = await inbox.wait_for_email()

        print(f"From: {email.from_address}")
        print(f"Subject: {email.subject}")
        print(f"Body: {email.text}")

        # Clean up
        await inbox.delete()

asyncio.run(main())
```

## Configuration

### Client Options

```python
from vaultsandbox import VaultSandboxClient, DeliveryStrategyType

client = VaultSandboxClient(
    api_key="your-api-key",
    base_url="https://smtp.vaultsandbox.com",  # Default
    timeout=30000,                              # HTTP timeout in ms
    max_retries=3,                              # Retry attempts
    retry_delay=1000,                           # Initial retry delay in ms
    strategy=DeliveryStrategyType.SSE,          # SSE or POLLING
)
```

### Environment Variables

Create a `.env` file:

```bash
VAULTSANDBOX_URL=https://smtp.vaultsandbox.com
VAULTSANDBOX_API_KEY=your-api-key-here
```

Load with `python-dotenv`:

```python
from dotenv import load_dotenv
import os

load_dotenv()

client = VaultSandboxClient(
    api_key=os.getenv("VAULTSANDBOX_API_KEY"),
    base_url=os.getenv("VAULTSANDBOX_URL"),
)
```

## Usage Examples

### Create Inbox with Options

```python
from vaultsandbox import CreateInboxOptions

# Custom TTL (time-to-live)
inbox = await client.create_inbox(
    CreateInboxOptions(ttl=3600)  # 1 hour
)

# Request specific email address prefix (server adds its domain)
inbox = await client.create_inbox(
    CreateInboxOptions(email_address="my-test-inbox")
)
```

### Wait for Email with Filters

```python
import re
from vaultsandbox import WaitForEmailOptions

# Wait for email with specific subject
email = await inbox.wait_for_email(
    WaitForEmailOptions(subject="Welcome")
)

# Wait for email from specific sender (regex)
email = await inbox.wait_for_email(
    WaitForEmailOptions(from_address=re.compile(r".*@company\.com"))
)

# Custom predicate
email = await inbox.wait_for_email(
    WaitForEmailOptions(
        predicate=lambda e: len(e.attachments) > 0,
        timeout=60000,  # 60 seconds
    )
)
```

### Wait for Multiple Emails

```python
from vaultsandbox import WaitForCountOptions

# Wait until inbox has at least 3 emails
emails = await inbox.wait_for_email_count(3, WaitForCountOptions(timeout=60000))
```

### Subscribe to New Emails

```python
async with VaultSandboxClient(api_key="your-api-key") as client:
    inbox = await client.create_inbox()

    async def handle_email(email):
        print(f"New email: {email.subject}")
        await email.mark_as_read()

    subscription = await inbox.on_new_email(handle_email)

    # Later, unsubscribe
    await inbox.unsubscribe(subscription)
```

### Monitor Multiple Inboxes

```python
inbox1 = await client.create_inbox()
inbox2 = await client.create_inbox()

def on_email(inbox, email):
    print(f"Email to {email.to}: {email.subject}")

monitor = client.monitor_inboxes([inbox1, inbox2])
monitor.on_email(on_email)
await monitor.start()

# ... wait for emails ...

await monitor.unsubscribe()
```

### Email Content and Attachments

```python
email = await inbox.wait_for_email()

# Text and HTML content
print(email.text)  # Plain text body
print(email.html)  # HTML body

# Headers
print(email.headers.get("message-id"))

# Attachments
for attachment in email.attachments:
    print(f"{attachment.filename}: {attachment.size} bytes")
    # attachment.content is bytes
    with open(attachment.filename, "wb") as f:
        f.write(attachment.content)

# Links found in the email
for link in email.links:
    print(link)

# Raw email source (MIME)
raw_email = await email.get_raw()
print(raw_email.id)   # Email ID
print(raw_email.raw)  # Raw MIME content
```

### Email Authentication Results

```python
email = await inbox.wait_for_email()

# Individual results
print(f"SPF: {email.auth_results.spf.result}")
print(f"DKIM: {[d.result for d in email.auth_results.dkim]}")
print(f"DMARC: {email.auth_results.dmarc.result}")

# Validate all at once
validation = email.auth_results.validate()
if validation.passed:
    print("All authentication checks passed")
else:
    print(f"Failures: {validation.failures}")
```

### Export and Import Inboxes

Export an inbox to persist its keypair:

```python
# Export to object
exported = client.export_inbox(inbox)

# Export to file
await client.export_inbox_to_file(inbox, "inbox_backup.json")
```

Import in a later session:

```python
# Import from object
inbox = await client.import_inbox(exported)

# Import from file
inbox = await client.import_inbox_from_file("inbox_backup.json")
```

> **Security Warning**: Exported data contains private keys. Store securely.

### Delete Inboxes

```python
# Delete single inbox
await inbox.delete()

# Delete all inboxes for API key
deleted_count = await client.delete_all_inboxes()
```

## API Reference

### VaultSandboxClient

The main client class for interacting with the VaultSandbox Gateway.

#### Constructor

```python
VaultSandboxClient(
    api_key: str,
    base_url: str = "https://smtp.vaultsandbox.com",
    timeout: int = 30000,
    max_retries: int = 3,
    retry_delay: int = 1000,
    strategy: DeliveryStrategyType = DeliveryStrategyType.SSE,
)
```

**Parameters:**

- `api_key: str` - Your API key
- `base_url: str` - Gateway URL (default: 'https://smtp.vaultsandbox.com')
- `timeout: int` - HTTP timeout in ms (default: 30000)
- `max_retries: int` - Max retry attempts for HTTP requests (default: 3)
- `retry_delay: int` - Delay in ms between retry attempts (default: 1000)
- `strategy: DeliveryStrategyType` - Delivery strategy: SSE or POLLING (default: SSE)

#### Methods

| Method | Description |
|--------|-------------|
| `check_key()` | Validate the API key |
| `get_server_info()` | Get server capabilities |
| `create_inbox(options?)` | Create a temporary inbox |
| `delete_all_inboxes()` | Delete all inboxes for API key |
| `monitor_inboxes(inboxes)` | Monitor multiple inboxes |
| `export_inbox(inbox)` | Export inbox data |
| `import_inbox(data)` | Import inbox from data |
| `export_inbox_to_file(inbox, path)` | Export inbox to JSON file |
| `import_inbox_from_file(path)` | Import inbox from JSON file |
| `close()` | Close client and release resources |

**Inbox Import/Export:** For advanced use cases like test reproducibility or sharing inboxes between environments, you can export an inbox (including its encryption keys) to a JSON file and import it later. This allows you to persist inboxes across test runs or share them with other tools.

### Inbox

Represents a single email inbox.

#### Properties

- `email_address: str` - The inbox email address
- `inbox_hash: str` - Unique inbox identifier
- `expires_at: datetime` - When the inbox expires

#### Methods

| Method | Description |
|--------|-------------|
| `list_emails()` | List all emails |
| `get_email(id)` | Get specific email |
| `get_raw_email(id)` | Get raw MIME source (returns `RawEmail`) |
| `wait_for_email(options?)` | Wait for matching email |
| `wait_for_email_count(n, options?)` | Wait for N emails |
| `on_new_email(callback)` | Subscribe to new emails |
| `mark_email_as_read(id)` | Mark email as read |
| `delete_email(id)` | Delete email |
| `delete()` | Delete inbox |
| `get_sync_status()` | Get email count and hash |
| `export()` | Export inbox data |

### Email

Represents a decrypted email.

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `id` | `str` | Unique email ID |
| `from_address` | `str` | Sender address |
| `to` | `list[str]` | Recipient addresses |
| `subject` | `str` | Email subject |
| `text` | `str \| None` | Plain text body |
| `html` | `str \| None` | HTML body |
| `attachments` | `list[Attachment]` | File attachments |
| `links` | `list[str]` | URLs in email |
| `headers` | `dict` | Email headers |
| `auth_results` | `AuthResults` | SPF/DKIM/DMARC results |
| `received_at` | `datetime` | When received |
| `is_read` | `bool` | Read status |

#### Methods

| Method | Description |
|--------|-------------|
| `mark_as_read()` | Mark as read |
| `delete()` | Delete email |
| `get_raw()` | Get raw MIME source (returns `RawEmail`) |

### AuthResults

Returned by `email.auth_results`, this object contains email authentication results (SPF, DKIM, DMARC) and a validation helper.

#### Properties

- `spf: SPFResult | None` - SPF result
- `dkim: list[DKIMResult] | None` - All DKIM results
- `dmarc: DMARCResult | None` - DMARC result
- `reverse_dns: ReverseDNSResult | None` - Reverse DNS result

#### Methods

- `validate() -> AuthResultsValidation` - Validates all authentication results and returns a summary object with `passed` (bool), individual results (`spf_passed`, `dkim_passed`, `dmarc_passed`, `reverse_dns_passed`), and `failures` (list of failure descriptions).

### CreateInboxOptions

Options for creating an inbox with `client.create_inbox()`.

**Properties:**

- `ttl: int | None` - Time-to-live for the inbox in seconds (default: server-defined).
- `email_address: str | None` - A specific email address to request. If unavailable, the server will generate one.

### WaitForEmailOptions

Options for waiting for emails with `inbox.wait_for_email()`.

**Properties:**

- `timeout: int | None` - Maximum time to wait in milliseconds (default: 30000)
- `poll_interval: int | None` - Polling interval in milliseconds (default: 2000)
- `subject: str | Pattern | None` - Filter emails by subject
- `from_address: str | Pattern | None` - Filter emails by sender address
- `predicate: Callable[[Email], bool] | None` - Custom filter function

### WaitForCountOptions

Options for waiting for a specific number of emails with `inbox.wait_for_email_count()`.

**Properties:**

- `timeout: int | None` - Maximum time to wait in milliseconds (default: 30000)

### RawEmail

Represents raw email content returned by `email.get_raw()` and `inbox.get_raw_email()`.

**Properties:**

- `id: str` - The email ID
- `raw: str` - The raw MIME email content

## Error Handling

The SDK is designed to be resilient and provide clear feedback when issues occur. It includes automatic retries for transient network and server errors, and raises specific, catchable errors for different failure scenarios.

All custom errors raised by the SDK extend from the base `VaultSandboxError` class, so you can catch all SDK-specific errors with a single `except` block if needed.

### Automatic Retries

By default, the client automatically retries failed HTTP requests that result in one of the following status codes: `408`, `429`, `500`, `502`, `503`, `504`. This helps mitigate transient network or server-side issues.

The retry behavior can be configured via the `VaultSandboxClient` constructor:

- `max_retries`: The maximum number of retry attempts (default: `3`).
- `retry_delay`: The base delay in milliseconds between retries (default: `1000`). The delay uses exponential backoff.
- `retry_on`: A list of HTTP status codes that should trigger a retry.

### Custom Error Types

The following custom error classes may be raised:

- **`ApiError`**: Raised for API-level errors (e.g., invalid request, permission denied). Includes a `status_code` property.
- **`NetworkError`**: Raised when there is a network-level failure (e.g., the client cannot connect to the server).
- **`TimeoutError`**: Raised by methods like `wait_for_email` and `wait_for_email_count` when the timeout is reached before the condition is met.
- **`InboxNotFoundError`**: Raised when an operation targets an inbox that does not exist (HTTP 404).
- **`EmailNotFoundError`**: Raised when an operation targets an email that does not exist (HTTP 404).
- **`InboxAlreadyExistsError`**: Raised when attempting to import an inbox that already exists in the client.
- **`InvalidImportDataError`**: Raised when imported inbox data fails validation (missing fields, invalid keys, server mismatch, etc.).
- **`DecryptionError`**: Raised if the client fails to decrypt an email. This is rare and may indicate data corruption or a bug.
- **`SignatureVerificationError`**: Raised if the cryptographic signature of a message from the server cannot be verified. This is a critical error that may indicate a man-in-the-middle (MITM) attack.
- **`SSEError`**: Raised for errors related to the Server-Sent Events (SSE) connection.

### Example

```python
from vaultsandbox import (
    VaultSandboxError,
    ApiError,
    NetworkError,
    TimeoutError,
    InboxNotFoundError,
    EmailNotFoundError,
    DecryptionError,
    SignatureVerificationError,
)

try:
    email = await inbox.wait_for_email(
        WaitForEmailOptions(timeout=5000)
    )
except TimeoutError:
    print("No email received within timeout")
except SignatureVerificationError:
    print("CRITICAL: Email signature verification failed!")
except DecryptionError as e:
    print(f"Failed to decrypt email: {e}")
except ApiError as e:
    print(f"API error {e.status_code}: {e.message}")
except NetworkError:
    print("Network connection failed")
except VaultSandboxError as e:
    print(f"VaultSandbox error: {e}")
```

## Requirements

- Python >= 3.10 (tested on Python 3.10, 3.11, 3.12, and 3.13)
- VaultSandbox Gateway server
- Valid API key

**Dependencies:**
- `httpx` - Async HTTP client
- `httpx-sse` - Server-Sent Events support
- `pqcrypto` - Post-quantum cryptography (ML-KEM-768, ML-DSA-65)
- `cryptography` - AES-256-GCM and HKDF

## Testing

```bash
# Run unit tests
pytest

# Run tests with coverage
pytest --cov=vaultsandbox
```

## Building

```bash
# Build package
python -m build

# Clean build artifacts
rm -rf dist/ build/ *.egg-info
```

## Architecture

The SDK is built on several layers:

1. **Crypto Layer**: Handles ML-KEM-768 keypair generation, AES-256-GCM encryption/decryption, and ML-DSA-65 signature verification
2. **HTTP Layer**: REST API client with automatic retry and error handling
3. **Domain Layer**: Email, Inbox, and Client classes with intuitive APIs
4. **Strategy Layer**: SSE and polling strategies for email delivery

All cryptographic operations are performed transparently - developers never need to handle keys, encryption, or signatures directly.

## Security

- Cryptography: ML-KEM-768 (Kyber768) for key encapsulation + AES-256-GCM for payload encryption, with HKDF-SHA-512 key derivation.
- Signatures: ML-DSA-65 (Dilithium3) signatures are verified **before** any decryption using the gateway-provided transcript context (`vaultsandbox:email:v1` today).
- Threat model: protects confidentiality/integrity of gateway responses and detects tampering/mitm. Skipping signature verification defeats these guarantees.
- Key handling: inbox keypairs stay in memory only; exported inbox data contains secrets and must be treated as sensitive.
- Validation: signature verification failures raise `SignatureVerificationError`; decryption issues raise `DecryptionError`. Always surface these in logs/alerts for investigation.

## Related

- [VaultSandbox Gateway](https://github.com/vaultsandbox/gateway) — The self-hosted SMTP server this SDK connects to
- [VaultSandbox Documentation](https://vaultsandbox.dev) — Full documentation and guides

## Support

- [Documentation](https://vaultsandbox.dev/client-python/)
- [Issue Tracker](https://github.com/vaultsandbox/client-python/issues)
- [Discussions](https://github.com/vaultsandbox/gateway/discussions)
- [Website](https://www.vaultsandbox.com)

## Contributing

Contributions are welcome! Please read our [contributing guidelines](CONTRIBUTING.md) before submitting PRs.

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.
