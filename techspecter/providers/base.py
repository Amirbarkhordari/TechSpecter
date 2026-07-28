"""Detection provider base protocol."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from techspecter.providers.models import (
    ProviderDetectionResult,
    ProviderHealthState,
    ProviderHealthStatus,
    ProviderTarget,
)


@runtime_checkable
class DetectionProvider(Protocol):
    """Passive detection provider interface."""

    @property
    def provider_id(self) -> str:
        """Unique provider identifier."""

    @property
    def display_name(self) -> str:
        """Human-readable provider name."""

    def is_available(self) -> bool:
        """Return whether the provider can run in the current environment."""

    def check_health(self) -> ProviderHealthStatus:
        """Return pre-execution health information."""

    def detect(self, target: ProviderTarget) -> ProviderDetectionResult:
        """Run passive detection against a target."""


class BaseDetectionProvider:
    """Base class with shared provider utilities."""

    provider_id: str = "base"
    display_name: str = "Base Provider"

    def is_available(self) -> bool:
        """Providers are available by default."""
        return True

    def check_health(self) -> ProviderHealthStatus:
        """Default health check for built-in providers."""
        state = (
            ProviderHealthState.AVAILABLE
            if self.is_available()
            else ProviderHealthState.UNAVAILABLE
        )
        return ProviderHealthStatus(
            provider_id=self.provider_id,
            display_name=self.display_name,
            state=state,
            backend_id=self.provider_id,
            reason=None if self.is_available() else "Provider unavailable",
        )

    def _failure_result(
        self,
        target: ProviderTarget,
        *,
        error: str,
        elapsed_ms: float = 0.0,
        health: ProviderHealthStatus | None = None,
        backend_id: str | None = None,
    ) -> ProviderDetectionResult:
        """Build a failed provider result."""
        return ProviderDetectionResult(
            provider=self.provider_id,
            target_url=target.url,
            matches=[],
            elapsed_ms=elapsed_ms,
            success=False,
            error=error,
            health=health,
            backend_id=backend_id,
        )
