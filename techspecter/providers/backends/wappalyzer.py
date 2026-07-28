"""Wappalyzer backend abstractions."""

from __future__ import annotations

import logging
from typing import Any, Protocol, runtime_checkable

from techspecter.providers.backends.wappalyzer_compat import WappalyzerCompatibilityLayer

logger = logging.getLogger(__name__)


@runtime_checkable
class WappalyzerBackend(Protocol):
    """Abstraction for Wappalyzer data collection implementations."""

    def is_available(self) -> bool:
        """Return whether this backend can run."""

    def detect(self, target_url: str, *, timeout_seconds: int) -> dict[str, Any] | list[Any]:
        """Collect Wappalyzer technology data for a target URL."""

    def backend_id(self) -> str | None:
        """Return active backend identifier."""

    def backend_version(self) -> str | None:
        """Return active backend version when known."""

    def unavailable_reason(self) -> str:
        """Explain why the backend is unavailable."""


class CliWappalyzerBackend:
    """Wappalyzer backend using the compatibility layer (optional dependency)."""

    def __init__(self, layer: WappalyzerCompatibilityLayer | None = None) -> None:
        """Initialize with injectable compatibility layer for testing."""
        self._layer = layer or WappalyzerCompatibilityLayer()

    def is_available(self) -> bool:
        """Return whether any Wappalyzer adapter is available."""
        try:
            return self._layer.is_available()
        except Exception as exc:
            logger.debug("Wappalyzer availability check failed: %s", exc)
            return False

    def detect(self, target_url: str, *, timeout_seconds: int) -> dict[str, Any] | list[Any]:
        """Run Wappalyzer via the selected adapter."""
        return self._layer.detect(target_url, timeout_seconds=timeout_seconds)

    def backend_id(self) -> str | None:
        """Return selected adapter identifier."""
        return self._layer.backend_id()

    def backend_version(self) -> str | None:
        """Return selected adapter version."""
        return self._layer.version()

    def unavailable_reason(self) -> str:
        """Return skip reason for structured logging."""
        return self._layer.unavailable_reason()
