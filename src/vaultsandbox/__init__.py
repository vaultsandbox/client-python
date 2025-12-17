"""VaultSandbox Python SDK.

A Python client library for VaultSandbox - Secure, receive-only SMTP server
for QA/testing environments with quantum-safe encryption.

Example:
    ```python
    import asyncio
    from vaultsandbox import VaultSandboxClient

    async def main():
        async with VaultSandboxClient(api_key="your-api-key") as client:
            # Create a temporary inbox
            inbox = await client.create_inbox()
            print(f"Inbox created: {inbox.email_address}")

            # Wait for an email
            email = await inbox.wait_for_email()
            print(f"Received: {email.subject}")
            print(f"From: {email.from_address}")
            print(f"Body: {email.text}")

    asyncio.run(main())
    ```
"""

from .client import InboxEmailCallback, InboxMonitor, VaultSandboxClient
from .constants import (
    DEFAULT_MAX_RETRIES,
    DEFAULT_POLLING_INTERVAL_MS,
    DEFAULT_POLLING_MAX_BACKOFF_MS,
    DEFAULT_RETRY_DELAY_MS,
    DEFAULT_RETRY_STATUS_CODES,
    DEFAULT_SSE_MAX_RECONNECT_ATTEMPTS,
    DEFAULT_SSE_RECONNECT_INTERVAL_MS,
    DEFAULT_TIMEOUT_MS,
)
from .email import Email
from .errors import (
    ApiError,
    DecryptionError,
    EmailNotFoundError,
    InboxAlreadyExistsError,
    InboxNotFoundError,
    InvalidImportDataError,
    NetworkError,
    SignatureVerificationError,
    SSEError,
    StrategyError,
    TimeoutError,
    VaultSandboxError,
)
from .inbox import Inbox
from .strategies import Subscription
from .types import (
    Attachment,
    AuthResults,
    AuthResultsValidation,
    ClientConfig,
    CreateInboxOptions,
    DeliveryStrategyType,
    DKIMResult,
    DKIMStatus,
    DMARCPolicy,
    DMARCResult,
    DMARCStatus,
    ExportedInbox,
    InboxData,
    PollingConfig,
    RawEmail,
    ReverseDNSResult,
    ReverseDNSStatus,
    ServerInfo,
    SPFResult,
    SPFStatus,
    SSEConfig,
    SyncStatus,
    WaitForCountOptions,
    WaitForEmailOptions,
)

__version__ = "0.5.0"

__all__ = [
    # Main classes
    "VaultSandboxClient",
    "InboxMonitor",
    "InboxEmailCallback",
    "Inbox",
    "Email",
    "Subscription",
    # Constants
    "DEFAULT_TIMEOUT_MS",
    "DEFAULT_RETRY_DELAY_MS",
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_POLLING_INTERVAL_MS",
    "DEFAULT_POLLING_MAX_BACKOFF_MS",
    "DEFAULT_SSE_RECONNECT_INTERVAL_MS",
    "DEFAULT_SSE_MAX_RECONNECT_ATTEMPTS",
    "DEFAULT_RETRY_STATUS_CODES",
    # Configuration
    "ClientConfig",
    "CreateInboxOptions",
    "DeliveryStrategyType",
    "PollingConfig",
    "SSEConfig",
    "WaitForCountOptions",
    "WaitForEmailOptions",
    # Data types
    "Attachment",
    "AuthResults",
    "AuthResultsValidation",
    "ExportedInbox",
    "InboxData",
    "RawEmail",
    "ServerInfo",
    "SyncStatus",
    # Authentication results
    "SPFResult",
    "SPFStatus",
    "DKIMResult",
    "DKIMStatus",
    "DMARCResult",
    "DMARCStatus",
    "DMARCPolicy",
    "ReverseDNSResult",
    "ReverseDNSStatus",
    # Errors
    "VaultSandboxError",
    "ApiError",
    "NetworkError",
    "TimeoutError",
    "InboxNotFoundError",
    "EmailNotFoundError",
    "InboxAlreadyExistsError",
    "InvalidImportDataError",
    "DecryptionError",
    "SignatureVerificationError",
    "SSEError",
    "StrategyError",
    # Version
    "__version__",
]
