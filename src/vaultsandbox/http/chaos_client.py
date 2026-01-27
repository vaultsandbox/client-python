"""Chaos configuration API client for VaultSandbox SDK."""

from __future__ import annotations

from typing import Any

from ..types import (
    BlackholeConfig,
    ChaosConfig,
    ConnectionDropConfig,
    GreylistConfig,
    LatencyConfig,
    RandomErrorConfig,
)
from .base_client import BaseApiClient, encode_path_segment


class ChaosApiClient(BaseApiClient):
    """API client for chaos configuration operations.

    Provides methods for getting and setting chaos configurations on inboxes.
    """

    def _serialize_latency_config(self, config: LatencyConfig) -> dict[str, Any]:
        """Serialize a LatencyConfig to API format."""
        result: dict[str, Any] = {"enabled": config.enabled}
        if config.min_delay_ms is not None:
            result["minDelayMs"] = config.min_delay_ms
        if config.max_delay_ms is not None:
            result["maxDelayMs"] = config.max_delay_ms
        if config.jitter is not None:
            result["jitter"] = config.jitter
        if config.probability is not None:
            result["probability"] = config.probability
        return result

    def _serialize_connection_drop_config(self, config: ConnectionDropConfig) -> dict[str, Any]:
        """Serialize a ConnectionDropConfig to API format."""
        result: dict[str, Any] = {"enabled": config.enabled}
        if config.probability is not None:
            result["probability"] = config.probability
        if config.graceful is not None:
            result["graceful"] = config.graceful
        return result

    def _serialize_random_error_config(self, config: RandomErrorConfig) -> dict[str, Any]:
        """Serialize a RandomErrorConfig to API format."""
        result: dict[str, Any] = {"enabled": config.enabled}
        if config.error_rate is not None:
            result["errorRate"] = config.error_rate
        if config.error_types is not None:
            result["errorTypes"] = config.error_types
        return result

    def _serialize_greylist_config(self, config: GreylistConfig) -> dict[str, Any]:
        """Serialize a GreylistConfig to API format."""
        result: dict[str, Any] = {"enabled": config.enabled}
        if config.retry_window_ms is not None:
            result["retryWindowMs"] = config.retry_window_ms
        if config.max_attempts is not None:
            result["maxAttempts"] = config.max_attempts
        if config.track_by is not None:
            result["trackBy"] = config.track_by
        return result

    def _serialize_blackhole_config(self, config: BlackholeConfig) -> dict[str, Any]:
        """Serialize a BlackholeConfig to API format."""
        result: dict[str, Any] = {"enabled": config.enabled}
        if config.trigger_webhooks is not None:
            result["triggerWebhooks"] = config.trigger_webhooks
        return result

    def _serialize_chaos_config(self, config: ChaosConfig) -> dict[str, Any]:
        """Serialize a ChaosConfig to API format."""
        result: dict[str, Any] = {"enabled": config.enabled}
        if config.expires_at is not None:
            result["expiresAt"] = config.expires_at
        if config.latency is not None:
            result["latency"] = self._serialize_latency_config(config.latency)
        if config.connection_drop is not None:
            result["connectionDrop"] = self._serialize_connection_drop_config(
                config.connection_drop
            )
        if config.random_error is not None:
            result["randomError"] = self._serialize_random_error_config(config.random_error)
        if config.greylist is not None:
            result["greylist"] = self._serialize_greylist_config(config.greylist)
        if config.blackhole is not None:
            result["blackhole"] = self._serialize_blackhole_config(config.blackhole)
        return result

    def _parse_latency_config(self, data: dict[str, Any]) -> LatencyConfig:
        """Parse LatencyConfig from API response."""
        return LatencyConfig(
            enabled=data["enabled"],
            min_delay_ms=data.get("minDelayMs"),
            max_delay_ms=data.get("maxDelayMs"),
            jitter=data.get("jitter"),
            probability=data.get("probability"),
        )

    def _parse_connection_drop_config(self, data: dict[str, Any]) -> ConnectionDropConfig:
        """Parse ConnectionDropConfig from API response."""
        return ConnectionDropConfig(
            enabled=data["enabled"],
            probability=data.get("probability"),
            graceful=data.get("graceful"),
        )

    def _parse_random_error_config(self, data: dict[str, Any]) -> RandomErrorConfig:
        """Parse RandomErrorConfig from API response."""
        return RandomErrorConfig(
            enabled=data["enabled"],
            error_rate=data.get("errorRate"),
            error_types=data.get("errorTypes"),
        )

    def _parse_greylist_config(self, data: dict[str, Any]) -> GreylistConfig:
        """Parse GreylistConfig from API response."""
        return GreylistConfig(
            enabled=data["enabled"],
            retry_window_ms=data.get("retryWindowMs"),
            max_attempts=data.get("maxAttempts"),
            track_by=data.get("trackBy"),
        )

    def _parse_blackhole_config(self, data: dict[str, Any]) -> BlackholeConfig:
        """Parse BlackholeConfig from API response."""
        return BlackholeConfig(
            enabled=data["enabled"],
            trigger_webhooks=data.get("triggerWebhooks"),
        )

    def _parse_chaos_config(self, data: dict[str, Any]) -> ChaosConfig:
        """Parse ChaosConfig from API response."""
        return ChaosConfig(
            enabled=data["enabled"],
            expires_at=data.get("expiresAt"),
            latency=self._parse_latency_config(data["latency"]) if data.get("latency") else None,
            connection_drop=self._parse_connection_drop_config(data["connectionDrop"])
            if data.get("connectionDrop")
            else None,
            random_error=self._parse_random_error_config(data["randomError"])
            if data.get("randomError")
            else None,
            greylist=self._parse_greylist_config(data["greylist"])
            if data.get("greylist")
            else None,
            blackhole=self._parse_blackhole_config(data["blackhole"])
            if data.get("blackhole")
            else None,
        )

    async def get_inbox_chaos(self, email_address: str) -> ChaosConfig:
        """Get the chaos configuration for an inbox.

        Args:
            email_address: The email address of the inbox.

        Returns:
            ChaosConfig with current chaos settings.

        Raises:
            ApiError: If chaos is disabled globally (403) or other API errors.
            InboxNotFoundError: If the inbox is not found.
        """
        encoded = encode_path_segment(email_address)
        response = await self._request("GET", f"/api/inboxes/{encoded}/chaos")
        return self._parse_chaos_config(response.json())

    async def set_inbox_chaos(self, email_address: str, config: ChaosConfig) -> ChaosConfig:
        """Set the chaos configuration for an inbox.

        Args:
            email_address: The email address of the inbox.
            config: The chaos configuration to apply.

        Returns:
            ChaosConfig with the applied settings (including defaults).

        Raises:
            ApiError: If chaos is disabled globally (403) or validation fails (400).
            InboxNotFoundError: If the inbox is not found.
        """
        encoded = encode_path_segment(email_address)
        body = self._serialize_chaos_config(config)
        response = await self._request("POST", f"/api/inboxes/{encoded}/chaos", json=body)
        return self._parse_chaos_config(response.json())

    async def disable_inbox_chaos(self, email_address: str) -> None:
        """Disable all chaos for an inbox.

        Args:
            email_address: The email address of the inbox.

        Raises:
            ApiError: If chaos is disabled globally (403) or other API errors.
            InboxNotFoundError: If the inbox is not found.
        """
        encoded = encode_path_segment(email_address)
        await self._request("DELETE", f"/api/inboxes/{encoded}/chaos")
