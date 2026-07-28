"""Collector registry for evidence analyzers."""

from __future__ import annotations

import logging
from threading import Lock

from techspecter.fingerprinting.analyzers.base import EvidenceCollector

logger = logging.getLogger(__name__)


class CollectorRegistry:
    """Register and resolve evidence collectors without hardcoded lists."""

    def __init__(self) -> None:
        """Initialize an empty collector registry."""
        self._collectors: dict[str, EvidenceCollector] = {}
        self._lock = Lock()

    def register(self, collector: EvidenceCollector) -> None:
        """Register a collector by name."""
        with self._lock:
            if collector.name in self._collectors:
                logger.warning("Replacing existing collector '%s'", collector.name)
            self._collectors[collector.name] = collector
            logger.debug("Registered evidence collector '%s'", collector.name)

    def unregister(self, name: str) -> None:
        """Remove a collector from the registry."""
        with self._lock:
            self._collectors.pop(name, None)

    def get(self, name: str) -> EvidenceCollector | None:
        """Return a collector by name."""
        return self._collectors.get(name)

    def list_collectors(self) -> tuple[str, ...]:
        """Return registered collector names."""
        with self._lock:
            return tuple(sorted(self._collectors))

    def resolve(self) -> list[EvidenceCollector]:
        """Return collectors sorted by priority."""
        with self._lock:
            collectors = list(self._collectors.values())
        return sorted(collectors, key=lambda item: (item.priority, item.name))

    def clear(self) -> None:
        """Clear all registered collectors."""
        with self._lock:
            self._collectors.clear()


collector_registry = CollectorRegistry()
