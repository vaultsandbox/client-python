"""HTTP client for VaultSandbox SDK.

This module provides HTTP clients for the VaultSandbox API:
- ApiClient: Unified client with all operations (backward compatible)
- BaseApiClient: Common HTTP operations and server endpoints
- InboxApiClient: Inbox CRUD operations
- EmailApiClient: Email operations
- WebhookApiClient: Webhook operations
- ChaosApiClient: Chaos configuration operations
"""

from .api_client import (
    ApiClient,
    BaseApiClient,
    ChaosApiClient,
    EmailApiClient,
    InboxApiClient,
    WebhookApiClient,
    encode_path_segment,
    validate_webhook_url,
)

__all__ = [
    "ApiClient",
    "BaseApiClient",
    "ChaosApiClient",
    "EmailApiClient",
    "InboxApiClient",
    "WebhookApiClient",
    "encode_path_segment",
    "validate_webhook_url",
]
