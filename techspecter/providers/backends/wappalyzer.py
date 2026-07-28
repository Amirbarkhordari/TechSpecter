"""Wappalyzer backend abstractions."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from techspecter.benchmark.wappalyzer import WappalyzerExecutor


@runtime_checkable
class WappalyzerBackend(Protocol):
    """Abstraction for Wappalyzer data collection implementations."""

    def is_available(self) -> bool:
        """Return whether this backend can run."""

    def detect(self, target_url: str, *, timeout_seconds: int) -> dict[str, Any] | list[Any]:
        """Collect Wappalyzer technology data for a target URL."""


class CliWappalyzerBackend:
    """Wappalyzer CLI backend (optional dependency)."""

    def __init__(self, executor: WappalyzerExecutor | None = None) -> None:
        """Initialize with an injectable executor for testing."""
        self._executor = executor

    def _executor_instance(self) -> WappalyzerExecutor:
        if self._executor is not None:
            return self._executor
        from techspecter.benchmark.wappalyzer import WappalyzerExecutor

        return WappalyzerExecutor()

    def is_available(self) -> bool:
        """Return whether the Wappalyzer CLI appears installed."""
        try:
            return self._executor_instance().is_available()
        except Exception as exc:
            logger.debug("Wappalyzer availability check failed: %s", exc)
            return False

    def detect(self, target_url: str, *, timeout_seconds: int) -> dict[str, Any] | list[Any]:
        """Run Wappalyzer CLI against the target URL."""
        return self._executor_instance().run(target_url, timeout_seconds=timeout_seconds)
