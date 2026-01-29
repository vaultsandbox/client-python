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
    InvalidAlgorithmError,
    InvalidImportDataError,
    InvalidPayloadError,
    InvalidSizeError,
    InvalidTimestampError,
    NetworkError,
    ServerKeyMismatchError,
    SignatureVerificationError,
    SSEError,
    StrategyError,
    TimeoutError,
    UnsupportedVersionError,
    VaultSandboxError,
    WebhookLimitReachedError,
    WebhookNotFoundError,
    WebhookSignatureVerificationError,
)
from .inbox import Inbox
from .strategies import Subscription
from .types import (
    Attachment,
    AuthResults,
    AuthResultsValidation,
    BlackholeConfig,
    ChaosConfig,
    ClientConfig,
    ConnectionDropConfig,
    CreateInboxOptions,
    CreateWebhookOptions,
    CustomTemplate,
    DeliveryStrategyType,
    DKIMResult,
    DKIMStatus,
    DMARCPolicy,
    DMARCResult,
    DMARCStatus,
    EmailMetadata,
    EncryptionPolicy,
    ExportedInbox,
    FilterableField,
    FilterConfig,
    FilterOperator,
    FilterRule,
    GreylistConfig,
    GreylistTrackBy,
    InboxData,
    InboxEncryptionMode,
    LatencyConfig,
    PollingConfig,
    RandomErrorConfig,
    RandomErrorType,
    RawEmail,
    ReverseDNSResult,
    ReverseDNSStatus,
    RotateSecretResult,
    ServerInfo,
    SpamAction,
    SpamAnalysisResult,
    SpamAnalysisStatus,
    SpamSymbol,
    SPFResult,
    SPFStatus,
    SSEConfig,
    SyncStatus,
    TestWebhookResult,
    UpdateWebhookOptions,
    WaitForCountOptions,
    WaitForEmailOptions,
    WebhookData,
    WebhookDeliveryStatus,
    WebhookEventType,
    WebhookListData,
    WebhookScope,
    WebhookStats,
    WebhookTemplateName,
)
from .utils import (
    construct_webhook_event,
    is_timestamp_valid,
    verify_webhook_signature,
)
from .webhook import Webhook

__version__ = "0.9.2"

__all__ = [
    # Main classes
    "VaultSandboxClient",
    "InboxMonitor",
    "InboxEmailCallback",
    "Inbox",
    "Email",
    "Subscription",
    "Webhook",
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
    "EncryptionPolicy",
    "InboxEncryptionMode",
    "PollingConfig",
    "SSEConfig",
    "WaitForCountOptions",
    "WaitForEmailOptions",
    # Data types
    "Attachment",
    "AuthResults",
    "AuthResultsValidation",
    "EmailMetadata",
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
    # Spam analysis types
    "SpamAction",
    "SpamAnalysisResult",
    "SpamAnalysisStatus",
    "SpamSymbol",
    # Webhook types
    "CreateWebhookOptions",
    "CustomTemplate",
    "FilterConfig",
    "FilterOperator",
    "FilterRule",
    "FilterableField",
    "RotateSecretResult",
    "TestWebhookResult",
    "UpdateWebhookOptions",
    "WebhookData",
    "WebhookDeliveryStatus",
    "WebhookEventType",
    "WebhookListData",
    "WebhookScope",
    "WebhookStats",
    "WebhookTemplateName",
    # Chaos types
    "BlackholeConfig",
    "ChaosConfig",
    "ConnectionDropConfig",
    "GreylistConfig",
    "GreylistTrackBy",
    "LatencyConfig",
    "RandomErrorConfig",
    "RandomErrorType",
    # Webhook utilities
    "construct_webhook_event",
    "is_timestamp_valid",
    "verify_webhook_signature",
    # Errors (per Appendix C of VaultSandbox spec)
    "VaultSandboxError",
    "ApiError",
    "NetworkError",
    "TimeoutError",
    "InboxNotFoundError",
    "EmailNotFoundError",
    "InboxAlreadyExistsError",
    "InvalidImportDataError",
    "InvalidTimestampError",
    "DecryptionError",
    "SignatureVerificationError",
    "SSEError",
    "StrategyError",
    "UnsupportedVersionError",
    "InvalidPayloadError",
    "InvalidAlgorithmError",
    "InvalidSizeError",
    "ServerKeyMismatchError",
    "WebhookNotFoundError",
    "WebhookLimitReachedError",
    "WebhookSignatureVerificationError",
    # Version
    "__version__",
]
