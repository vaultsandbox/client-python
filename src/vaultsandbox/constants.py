"""Default configuration constants for VaultSandbox SDK."""

# HTTP settings (milliseconds)
DEFAULT_TIMEOUT_MS = 30_000
DEFAULT_RETRY_DELAY_MS = 1_000
DEFAULT_MAX_RETRIES = 3

# Polling strategy settings (milliseconds)
DEFAULT_POLLING_INTERVAL_MS = 2_000
DEFAULT_POLLING_MAX_BACKOFF_MS = 30_000

# SSE strategy settings
DEFAULT_SSE_RECONNECT_INTERVAL_MS = 5_000
DEFAULT_SSE_MAX_RECONNECT_ATTEMPTS = 10

# Default retry status codes
DEFAULT_RETRY_STATUS_CODES = (408, 429, 500, 502, 503, 504)
