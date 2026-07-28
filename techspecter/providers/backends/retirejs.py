"""Retire.js backend abstractions."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from techspecter.providers.retirejs import RetireJsExecutor


@runtime_checkable
class RetireJsBackend(Protocol):
    """Abstraction for Retire.js data collection implementations."""

    def is_available(self) -> bool:
        """Return whether this backend can run."""

    def scan_urls(self, urls: list[str], *, timeout_seconds: int) -> list[dict[str, Any]]:
        """Scan remote JavaScript URLs."""

    def scan_scripts(
        self,
        scripts: list[tuple[str, str]],
        *,
        timeout_seconds: int,
    ) -> list[dict[str, Any]]:
        """Scan in-memory JavaScript scripts."""


class CliRetireJsBackend:
    """Retire.js CLI backend (optional dependency)."""

    def __init__(self, executor: RetireJsExecutor | None = None) -> None:
        """Initialize with an injectable executor for testing."""
        self._executor = executor

    def _executor_instance(self) -> RetireJsExecutor:
        if self._executor is not None:
            return self._executor
        from techspecter.providers.retirejs import RetireJsExecutor

        return RetireJsExecutor()

    def is_available(self) -> bool:
        """Return whether Retire.js CLI appears installed."""
        try:
            return self._executor_instance().is_available()
        except Exception as exc:
            logger.debug("Retire.js availability check failed: %s", exc)
            return False

    def scan_urls(self, urls: list[str], *, timeout_seconds: int) -> list[dict[str, Any]]:
        """Scan URLs via Retire.js CLI."""
        return self._executor_instance().scan_urls(urls, timeout_seconds=timeout_seconds)

    def scan_scripts(
        self,
        scripts: list[tuple[str, str]],
        *,
        timeout_seconds: int,
    ) -> list[dict[str, Any]]:
        """Scan script content via Retire.js CLI."""
        return self._executor_instance().scan_discovery_scripts(
            scripts,
            timeout_seconds=timeout_seconds,
        )
