"""Type definitions for VaultSandbox SDK."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from re import Pattern
from typing import Any, Literal, TypedDict

# Encryption policy values
EncryptionPolicy = Literal["always", "enabled", "disabled", "never"]


class DeliveryStrategyType(str, Enum):
    """Delivery strategy types."""

    SSE = "sse"
    POLLING = "polling"


@dataclass
class ClientConfig:
    """Configuration for VaultSandboxClient.

    Attributes:
        api_key: API key for authentication.
        base_url: Base URL for the API server.
        timeout: HTTP request timeout in milliseconds.
        max_retries: Maximum number of retry attempts.
        retry_delay: Initial retry delay in milliseconds.
        retry_on_status_codes: HTTP status codes to retry on.
        strategy: Delivery strategy type.
    """

    api_key: str
    base_url: str = "https://smtp.vaultsandbox.com"
    timeout: int = 30000
    max_retries: int = 3
    retry_delay: int = 1000
    retry_on_status_codes: tuple[int, ...] = (408, 429, 500, 502, 503, 504)
    strategy: DeliveryStrategyType = DeliveryStrategyType.SSE


# Inbox encryption mode values
InboxEncryptionMode = Literal["encrypted", "plain"]


@dataclass
class CreateInboxOptions:
    """Options for creating an inbox.

    Attributes:
        ttl: Time-to-live in seconds (min: 60, max: 604800).
        email_address: Desired email address or domain (max 254 chars).
        email_auth: Enable/disable email authentication checks. None uses server default.
        encryption: Encryption mode for the inbox ('encrypted' or 'plain').
            - None: Use server default (encrypted if policy is 'always' or 'enabled')
            - 'encrypted': Force encrypted inbox (requires policy to allow)
            - 'plain': Force plain inbox (requires policy to allow)
        spam_analysis: Enable/disable spam analysis for this inbox.
            - None: Use server default
            - True: Enable spam analysis
            - False: Disable spam analysis
        chaos: Initial chaos configuration for this inbox.
            Requires chaos to be enabled globally on the server.
    """

    ttl: int | None = None
    email_address: str | None = None
    email_auth: bool | None = None
    encryption: InboxEncryptionMode | None = None
    spam_analysis: bool | None = None
    chaos: ChaosConfig | None = None


@dataclass
class ServerInfo:
    """Server information and capabilities.

    Attributes:
        server_sig_pk: Base64URL-encoded server signing public key.
        algs: Cryptographic algorithms supported by the server.
        context: Context string for the encryption scheme.
        max_ttl: Maximum time-to-live for inboxes in seconds.
        default_ttl: Default time-to-live for inboxes in seconds.
        sse_console: Whether server SSE console logging is enabled.
        allowed_domains: List of domains allowed for inbox creation.
        encryption_policy: Server encryption policy ('always', 'enabled', 'disabled', 'never').
        spam_analysis_enabled: Whether spam analysis (Rspamd) is enabled on this server.
        chaos_enabled: Whether chaos engineering is enabled globally on this server.
    """

    server_sig_pk: str
    algs: dict[str, str]
    context: str
    max_ttl: int
    default_ttl: int
    sse_console: bool
    allowed_domains: list[str]
    encryption_policy: EncryptionPolicy = "always"
    spam_analysis_enabled: bool = False
    chaos_enabled: bool = False


@dataclass
class SyncStatus:
    """Inbox sync status.

    Attributes:
        email_count: Number of emails in the inbox.
        emails_hash: Hash of email IDs for change detection.
    """

    email_count: int
    emails_hash: str


@dataclass
class RawEmail:
    """Raw email content.

    Attributes:
        id: The email ID.
        raw: The raw MIME email content.
    """

    id: str
    raw: str


@dataclass
class EmailMetadata:
    """Email metadata without full content.

    Attributes:
        id: The email ID.
        from_address: Sender email address.
        subject: Email subject.
        received_at: When the email was received.
        is_read: Whether the email has been read.
    """

    id: str
    from_address: str
    subject: str
    received_at: datetime
    is_read: bool


@dataclass
class InboxData:
    """Data returned when creating an inbox.

    Attributes:
        email_address: The email address assigned to the inbox.
        expires_at: ISO 8601 timestamp when the inbox will expire.
        inbox_hash: SHA-256 hash of the client KEM public key (or email for plain inboxes).
        encrypted: Whether the inbox uses encryption.
        server_sig_pk: Server signing public key for verification (only present when encrypted).
        email_auth: Whether email authentication checks are enabled.
    """

    email_address: str
    expires_at: str
    inbox_hash: str
    encrypted: bool
    email_auth: bool
    server_sig_pk: str | None = None


@dataclass
class ExportedInbox:
    """Exported inbox data for persistence/sharing.

    Per VaultSandbox spec Section 9, the export format includes:
    - version: Export format version (must be 1)
    - emailAddress: The inbox email address
    - expiresAt: Inbox expiration timestamp (ISO 8601)
    - inboxHash: Unique inbox identifier
    - encrypted: Whether the inbox uses encryption
    - emailAuth: Whether email authentication checks are enabled
    - serverSigPk: Server's ML-DSA-65 public key (base64url) - only for encrypted inboxes
    - secretKey: ML-KEM-768 secret key (base64url, 2400 bytes decoded) - only for encrypted inboxes
    - exportedAt: Export timestamp (ISO 8601)

    Note: Public key is NOT included as it can be derived from secret key.

    Attributes:
        version: Export format version (always 1).
        email_address: The email address assigned to the inbox.
        expires_at: ISO 8601 timestamp when the inbox will expire.
        inbox_hash: Unique inbox identifier.
        encrypted: Whether the inbox uses encryption.
        email_auth: Whether email authentication checks are enabled.
        exported_at: ISO 8601 timestamp when the inbox was exported.
        server_sig_pk: Server signing public key (base64url encoded) - only for encrypted inboxes.
        secret_key: ML-KEM-768 secret key (base64url encoded) - only for encrypted inboxes.
    """

    version: int
    email_address: str
    expires_at: str
    inbox_hash: str
    encrypted: bool
    email_auth: bool
    exported_at: str
    server_sig_pk: str | None = None
    secret_key: str | None = None


# SPF status values
class SPFStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    SKIPPED = "skipped"


# DKIM status values
class DKIMStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NONE = "none"
    SKIPPED = "skipped"


# DMARC status values
class DMARCStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NONE = "none"
    SKIPPED = "skipped"


# Reverse DNS status values
class ReverseDNSStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NONE = "none"
    SKIPPED = "skipped"


# DMARC policy values
class DMARCPolicy(str, Enum):
    NONE = "none"
    QUARANTINE = "quarantine"
    REJECT = "reject"


# Spam analysis status values
class SpamAnalysisStatus(str, Enum):
    """Status of spam analysis for an email."""

    ANALYZED = "analyzed"
    SKIPPED = "skipped"
    ERROR = "error"


# Spam analysis action values
class SpamAction(str, Enum):
    """Recommended action from spam analysis."""

    NO_ACTION = "no action"
    GREYLIST = "greylist"
    ADD_HEADER = "add header"
    REWRITE_SUBJECT = "rewrite subject"
    SOFT_REJECT = "soft reject"
    REJECT = "reject"


@dataclass
class SPFResult:
    """SPF validation result.

    Attributes:
        result: SPF result status.
        domain: Domain that was checked.
        ip: IP address that was checked.
        details: Additional details.
    """

    result: SPFStatus
    domain: str | None = None
    ip: str | None = None
    details: str | None = None


@dataclass
class DKIMResult:
    """DKIM validation result.

    Attributes:
        result: DKIM result status.
        domain: Domain that was checked.
        selector: DKIM selector used.
        signature: DKIM signature information.
    """

    result: DKIMStatus
    domain: str | None = None
    selector: str | None = None
    signature: str | None = None


@dataclass
class DMARCResult:
    """DMARC validation result.

    Attributes:
        result: DMARC result status.
        policy: DMARC policy.
        aligned: Whether DMARC is aligned.
        domain: Domain that was checked.
    """

    result: DMARCStatus
    policy: DMARCPolicy | None = None
    aligned: bool | None = None
    domain: str | None = None


@dataclass
class ReverseDNSResult:
    """Reverse DNS validation result.

    Attributes:
        result: Reverse DNS result status.
        ip: IP address that was checked.
        hostname: Hostname from PTR record.
    """

    result: ReverseDNSStatus
    ip: str | None = None
    hostname: str | None = None


@dataclass
class AuthResultsValidation:
    """Summary of authentication results validation.

    Attributes:
        passed: Whether all checks passed.
        spf_passed: Whether SPF check passed.
        dkim_passed: Whether DKIM check passed.
        dmarc_passed: Whether DMARC check passed.
        reverse_dns_passed: Whether reverse DNS check passed.
        failures: List of failure descriptions.
    """

    passed: bool
    spf_passed: bool
    dkim_passed: bool
    dmarc_passed: bool
    reverse_dns_passed: bool
    failures: list[str] = field(default_factory=list)


@dataclass
class AuthResults:
    """Email authentication results.

    Attributes:
        spf: SPF validation result.
        dkim: List of DKIM validation results.
        dmarc: DMARC validation result.
        reverse_dns: Reverse DNS validation result.
    """

    spf: SPFResult | None = None
    dkim: list[DKIMResult] = field(default_factory=list)
    dmarc: DMARCResult | None = None
    reverse_dns: ReverseDNSResult | None = None

    def validate(self) -> AuthResultsValidation:
        """Validate authentication results.

        Returns:
            AuthResultsValidation with passed flag, individual results, and any failures.

        Note:
            'skipped' status is treated as passing (not a failure) since it indicates
            authentication checks were disabled for the inbox.
        """
        failures: list[str] = []

        # Check SPF - 'pass' or 'skipped' counts as passed
        spf_passed = self.spf.result in (SPFStatus.PASS, SPFStatus.SKIPPED) if self.spf else False
        if self.spf and not spf_passed:
            domain_info = f" (domain: {self.spf.domain})" if self.spf.domain else ""
            failures.append(f"SPF check failed: {self.spf.result.value}{domain_info}")

        # Check DKIM - at least one signature must pass, or all skipped
        if self.dkim:
            has_pass = any(d.result == DKIMStatus.PASS for d in self.dkim)
            all_skipped = all(d.result == DKIMStatus.SKIPPED for d in self.dkim)
            dkim_passed = has_pass or all_skipped
        else:
            dkim_passed = False
        if self.dkim and len(self.dkim) > 0 and not dkim_passed:
            failed_domains = ", ".join(
                d.domain
                for d in self.dkim
                if d.result not in (DKIMStatus.PASS, DKIMStatus.SKIPPED) and d.domain
            )
            failures.append(
                f"DKIM signature failed{': ' + failed_domains if failed_domains else ''}"
            )

        # Check DMARC - 'pass' or 'skipped' counts as passed
        dmarc_passed = (
            self.dmarc.result in (DMARCStatus.PASS, DMARCStatus.SKIPPED) if self.dmarc else False
        )
        if self.dmarc and not dmarc_passed:
            policy_info = f" (policy: {self.dmarc.policy.value})" if self.dmarc.policy else ""
            failures.append(f"DMARC policy: {self.dmarc.result.value}{policy_info}")

        # Check Reverse DNS - 'pass' or 'skipped' counts as passed
        reverse_dns_passed = (
            self.reverse_dns.result in (ReverseDNSStatus.PASS, ReverseDNSStatus.SKIPPED)
            if self.reverse_dns
            else False
        )
        if self.reverse_dns and not reverse_dns_passed:
            hostname_info = (
                f" (hostname: {self.reverse_dns.hostname})" if self.reverse_dns.hostname else ""
            )
            failures.append(f"Reverse DNS check failed{hostname_info}")

        return AuthResultsValidation(
            passed=spf_passed and dkim_passed and dmarc_passed,
            spf_passed=spf_passed,
            dkim_passed=dkim_passed,
            dmarc_passed=dmarc_passed,
            reverse_dns_passed=reverse_dns_passed,
            failures=failures,
        )


@dataclass
class SpamSymbol:
    """Individual spam rule/symbol that was triggered.

    Attributes:
        name: Rule identifier (e.g., 'DKIM_SIGNED', 'FORGED_SENDER').
        score: Score contribution (positive = spam indicator, negative = legitimacy indicator).
        description: Human-readable description of what this rule detects.
        options: Additional context or matched values (e.g., matched URLs).
    """

    name: str
    score: float
    description: str | None = None
    options: list[str] | None = None


@dataclass
class SpamAnalysisResult:
    """Result of spam analysis for an email.

    Attributes:
        status: Analysis status ('analyzed', 'skipped', or 'error').
        score: Overall spam score (positive = more spammy). Only present when status is 'analyzed'.
        required_score: Threshold for spam classification. Emails with score >= required_score are spam.
        action: Recommended action from spam analysis.
        is_spam: Whether the email is classified as spam (score >= required_score).
        symbols: List of triggered spam rules/symbols with their scores.
        processing_time_ms: Time taken for spam analysis in milliseconds.
        info: Additional information (error message or skip reason).
    """

    status: SpamAnalysisStatus
    score: float | None = None
    required_score: float | None = None
    action: SpamAction | None = None
    is_spam: bool | None = None
    symbols: list[SpamSymbol] = field(default_factory=list)
    processing_time_ms: int | None = None
    info: str | None = None


@dataclass
class Attachment:
    """Email attachment.

    Attributes:
        filename: Attachment filename.
        content_type: MIME content type.
        size: Attachment size in bytes.
        content_id: Content ID for inline attachments.
        content_disposition: Content disposition (attachment/inline).
        content: Attachment content as bytes.
        checksum: Optional SHA-256 hash of the attachment content.
    """

    filename: str
    content_type: str
    size: int
    content: bytes
    content_id: str | None = None
    content_disposition: str | None = None
    checksum: str | None = None


@dataclass
class WaitForEmailOptions:
    """Options for waiting for an email.

    Attributes:
        subject: Match email subject (string or regex pattern).
        from_address: Match sender address (string or regex pattern).
        predicate: Custom filter function.
        timeout: Max wait time in milliseconds.
        poll_interval: Polling interval in milliseconds.
    """

    subject: str | Pattern[str] | None = None
    from_address: str | Pattern[str] | None = None
    predicate: Callable[..., bool] | None = None
    timeout: int = 30000
    poll_interval: int = 2000


@dataclass
class WaitForCountOptions:
    """Options for waiting for a specific number of emails.

    Attributes:
        timeout: Maximum wait time in milliseconds (default: 30000).
    """

    timeout: int = 30000


@dataclass
class PollingConfig:
    """Configuration for polling strategy.

    Attributes:
        initial_interval: Starting poll interval in milliseconds.
        max_backoff: Maximum backoff delay in milliseconds.
        backoff_multiplier: Backoff growth factor.
        jitter_factor: Random jitter (0-30%).
    """

    initial_interval: int = 2000
    max_backoff: int = 30000
    backoff_multiplier: float = 1.5
    jitter_factor: float = 0.3


ErrorCallback = Callable[[BaseException], None]


@dataclass
class SSEConfig:
    """Configuration for SSE strategy.

    Attributes:
        reconnect_interval: Initial reconnection interval in milliseconds.
        max_reconnect_attempts: Maximum reconnection attempts.
        on_error: Callback invoked when SSE connection fails permanently.
    """

    reconnect_interval: int = 5000
    max_reconnect_attempts: int = 10
    on_error: ErrorCallback | None = None


# Type alias for email filter matcher
EmailFilterMatcher = str | Pattern[str]


class EncryptedPayload(TypedDict):
    """Encrypted payload structure from server."""

    v: int
    algs: dict[str, str]
    ct_kem: str
    nonce: str
    aad: str
    ciphertext: str
    sig: str
    server_sig_pk: str


class RawEmailResponse(TypedDict, total=False):
    """Raw email response from server.

    For encrypted inboxes: has 'encryptedRaw' field
    For plain inboxes: has 'raw' field (base64 encoded)
    Use 'encryptedRaw' in response to discriminate format.
    """

    id: str
    encryptedRaw: EncryptedPayload  # Encrypted inbox
    raw: str  # Plain inbox (base64 encoded)


class EmailResponse(TypedDict, total=False):
    """Email response from server.

    For encrypted inboxes: has 'encryptedMetadata' and 'encryptedParsed' fields
    For plain inboxes: has 'metadata' and 'parsed' fields (base64 encoded JSON)
    Use 'encryptedMetadata' in response to discriminate format.
    """

    id: str
    inboxId: str
    receivedAt: str
    isRead: bool
    # Encrypted inbox fields
    encryptedMetadata: EncryptedPayload
    encryptedParsed: EncryptedPayload
    # Plain inbox fields (base64 encoded JSON)
    metadata: str
    parsed: str


# Callback types
EmailCallback = Callable[..., None]
AsyncEmailCallback = Callable[..., Any]

# Webhook types

# Event types that webhooks can subscribe to
WebhookEventType = Literal["email.received", "email.stored", "email.deleted"]

# Filter operators for webhook filters
FilterOperator = Literal[
    "equals", "contains", "starts_with", "ends_with", "domain", "regex", "exists"
]

# Fields that can be filtered on
FilterableField = Literal[
    "subject",
    "from.address",
    "from.name",
    "to.address",
    "to.name",
    "body.text",
    "body.html",
]

# Built-in template names
WebhookTemplateName = Literal[
    "default", "slack", "discord", "teams", "simple", "notification", "zapier"
]

# Webhook scope
WebhookScope = Literal["global", "inbox"]

# Delivery status
WebhookDeliveryStatus = Literal["success", "failed"]


@dataclass
class FilterRule:
    """A single filter rule for webhook filtering.

    Attributes:
        field: Field to filter on.
        operator: Comparison operator.
        value: Value to match (max 1000 chars).
        case_sensitive: Case-sensitive matching (default: False).
    """

    field: str  # FilterableField or header.X-Custom
    operator: FilterOperator
    value: str
    case_sensitive: bool = False


@dataclass
class FilterConfig:
    """Filter configuration for webhooks.

    Attributes:
        rules: Filter rules (max 10).
        mode: 'all' = AND logic, 'any' = OR logic.
        require_auth: Require email to pass SPF/DKIM/DMARC checks.
    """

    rules: list[FilterRule]
    mode: Literal["all", "any"]
    require_auth: bool = False


@dataclass
class CustomTemplate:
    """Custom payload template for webhooks.

    Attributes:
        body: JSON template with {{variable}} placeholders (max 10000 chars).
        content_type: Optional Content-Type header override.
    """

    body: str
    content_type: str | None = None


@dataclass
class WebhookStats:
    """Webhook delivery statistics.

    Attributes:
        total_deliveries: Total number of delivery attempts.
        successful_deliveries: Number of successful deliveries.
        failed_deliveries: Number of failed deliveries.
    """

    total_deliveries: int
    successful_deliveries: int
    failed_deliveries: int


@dataclass
class WebhookData:
    """Webhook data returned from API.

    Attributes:
        id: Webhook ID (whk_ prefix).
        url: Target URL.
        events: Subscribed event types.
        scope: 'global' or 'inbox'.
        enabled: Whether webhook is active.
        created_at: ISO timestamp.
        inbox_email: Inbox email (inbox webhooks only).
        inbox_hash: Inbox hash (inbox webhooks only).
        secret: Signing secret (whsec_ prefix) - only on create/get, not list.
        template: Template configuration.
        filter: Filter configuration.
        description: Human-readable description.
        updated_at: ISO timestamp of last update.
        last_delivery_at: ISO timestamp of last delivery attempt.
        last_delivery_status: Status of last delivery.
        stats: Delivery statistics (only on get, not list).
    """

    id: str
    url: str
    events: list[str]
    scope: WebhookScope
    enabled: bool
    created_at: str
    inbox_email: str | None = None
    inbox_hash: str | None = None
    secret: str | None = None
    template: str | CustomTemplate | None = None
    filter: FilterConfig | None = None
    description: str | None = None
    updated_at: str | None = None
    last_delivery_at: str | None = None
    last_delivery_status: WebhookDeliveryStatus | None = None
    stats: WebhookStats | None = None


@dataclass
class WebhookListData:
    """Webhook list response from API.

    Attributes:
        webhooks: List of webhooks.
        total: Total count.
    """

    webhooks: list[WebhookData]
    total: int


@dataclass
class TestWebhookResult:
    """Result of testing a webhook.

    Attributes:
        success: Whether test succeeded.
        status_code: HTTP status code from endpoint.
        response_time: Response time in milliseconds.
        response_body: Response body (truncated to 1KB).
        error: Error message if failed.
        payload_sent: The test payload that was sent.
    """

    success: bool
    status_code: int | None = None
    response_time: int | None = None
    response_body: str | None = None
    error: str | None = None
    payload_sent: Any | None = None


@dataclass
class RotateSecretResult:
    """Result of rotating a webhook secret.

    Attributes:
        id: Webhook ID.
        secret: New signing secret.
        previous_secret_valid_until: ISO timestamp - old secret valid until this time.
    """

    id: str
    secret: str
    previous_secret_valid_until: str


@dataclass
class CreateWebhookOptions:
    """Options for creating a webhook.

    Attributes:
        url: Target URL (HTTPS required in production).
        events: Event types to subscribe to (max 10).
        template: Optional payload template name or custom template.
        filter: Optional event filter configuration.
        description: Optional description (max 500 chars).
    """

    url: str
    events: list[str]
    template: str | CustomTemplate | None = None
    filter: FilterConfig | None = None
    description: str | None = None


@dataclass
class UpdateWebhookOptions:
    """Options for updating a webhook. All fields are optional.

    Attributes:
        url: New target URL.
        events: New event types to subscribe to.
        template: New template (set to None to remove).
        filter: New filter config (set to None to remove).
        description: New description.
        enabled: Enable/disable the webhook.
    """

    url: str | None = None
    events: list[str] | None = None
    template: str | CustomTemplate | None = field(default=None)
    filter: FilterConfig | None = field(default=None)
    description: str | None = None
    enabled: bool | None = None
    # Special flags to explicitly remove template/filter (since None means "don't change")
    _remove_template: bool = field(default=False, repr=False)
    _remove_filter: bool = field(default=False, repr=False)


# Chaos configuration types

# Greylist tracking method values
GreylistTrackBy = Literal["ip", "sender", "ip_sender"]

# Random error type values
RandomErrorType = Literal["temporary", "permanent"]


@dataclass
class LatencyConfig:
    """Latency injection configuration for chaos testing.

    Injects artificial delays into email processing.

    Attributes:
        enabled: Enable latency injection.
        min_delay_ms: Minimum delay in milliseconds (default: 500).
        max_delay_ms: Maximum delay in milliseconds (default: 10000, max: 60000).
        jitter: Randomize delay within range. False = fixed at max_delay_ms (default: True).
        probability: Probability of applying delay, 0.0-1.0 (default: 1.0).
    """

    enabled: bool
    min_delay_ms: int | None = None
    max_delay_ms: int | None = None
    jitter: bool | None = None
    probability: float | None = None


@dataclass
class ConnectionDropConfig:
    """Connection drop configuration for chaos testing.

    Simulates connection failures by dropping the SMTP connection.
    Connection is always dropped after receiving email data, before sending 250 OK.

    Attributes:
        enabled: Enable connection dropping.
        probability: Probability of dropping, 0.0-1.0 (default: 1.0).
        graceful: Use graceful close (FIN) vs abrupt (RST) (default: True).
    """

    enabled: bool
    probability: float | None = None
    graceful: bool | None = None


@dataclass
class RandomErrorConfig:
    """Random error configuration for chaos testing.

    Returns random SMTP error codes.

    Attributes:
        enabled: Enable random error generation.
        error_rate: Probability of returning an error, 0.0-1.0 (default: 0.1).
        error_types: Types of errors to return (default: ["temporary"]).
            - "temporary": 4xx errors (421, 450, 451, 452).
            - "permanent": 5xx errors (550, 551, 552, 553, 554).
    """

    enabled: bool
    error_rate: float | None = None
    error_types: list[RandomErrorType] | None = None


@dataclass
class GreylistConfig:
    """Greylisting configuration for chaos testing.

    Simulates greylisting behavior (reject first attempt, accept on retry).

    Attributes:
        enabled: Enable greylisting simulation.
        retry_window_ms: Window for tracking retry attempts in milliseconds (default: 300000).
        max_attempts: Number of attempts before accepting (default: 2).
        track_by: How to identify unique senders (default: "ip_sender").
            - "ip": Track by sender IP address only.
            - "sender": Track by sender email address only.
            - "ip_sender": Track by combination of IP and sender email.
    """

    enabled: bool
    retry_window_ms: int | None = None
    max_attempts: int | None = None
    track_by: GreylistTrackBy | None = None


@dataclass
class BlackholeConfig:
    """Blackhole configuration for chaos testing.

    Accepts emails but silently discards them (does not store).

    Attributes:
        enabled: Enable blackhole mode.
        trigger_webhooks: Whether to still trigger webhooks (default: False).
    """

    enabled: bool
    trigger_webhooks: bool | None = None


@dataclass
class ChaosConfig:
    """Chaos configuration for an inbox.

    Chaos engineering allows controlled injection of failures and delays
    into email processing to test system resilience.

    When multiple chaos types are enabled, they are evaluated in priority order
    (first match wins):
    1. Connection Drop (most disruptive)
    2. Greylisting
    3. Random Error
    4. Blackhole
    5. Latency (least disruptive)

    Attributes:
        enabled: Master switch for chaos on this inbox.
        expires_at: Auto-disable chaos after this timestamp (ISO 8601).
        latency: Latency injection settings.
        connection_drop: Connection drop settings.
        random_error: Random error settings.
        greylist: Greylisting settings.
        blackhole: Blackhole mode settings.
    """

    enabled: bool
    expires_at: str | None = None
    latency: LatencyConfig | None = None
    connection_drop: ConnectionDropConfig | None = None
    random_error: RandomErrorConfig | None = None
    greylist: GreylistConfig | None = None
    blackhole: BlackholeConfig | None = None
