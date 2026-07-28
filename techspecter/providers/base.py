"""Detection provider base protocol."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from techspecter.providers.models import ProviderDetectionResult, ProviderTarget


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

    def detect(self, target: ProviderTarget) -> ProviderDetectionResult:
        """Run passive detection against a target."""


class BaseDetectionProvider:
    """Base class with shared provider utilities."""

    provider_id: str = "base"
    display_name: str = "Base Provider"

    def is_available(self) -> bool:
        """Providers are available by default."""
        return True

    def _failure_result(
        self,
        target: ProviderTarget,
        *,
        error: str,
        elapsed_ms: float = 0.0,
    ) -> ProviderDetectionResult:
        """Build a failed provider result."""
        return ProviderDetectionResult(
            provider=self.provider_id,
            target_url=target.url,
            matches=[],
            elapsed_ms=elapsed_ms,
            success=False,
            error=error,
        )
