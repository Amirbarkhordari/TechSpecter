"""Analyzer registry for extensible analysis modules."""

from __future__ import annotations

import logging

from techspecter.analysis.analyzers.base import Analyzer
from techspecter.exceptions import TechSpecterError

logger = logging.getLogger(__name__)


class AnalyzerNotFoundError(TechSpecterError):
    """Raised when a requested analyzer is not registered."""


class AnalyzerRegistry:
    """Central registry for analysis modules."""

    def __init__(self) -> None:
        """Initialize an empty analyzer registry."""
        self._analyzers: dict[str, Analyzer] = {}

    def register(self, analyzer: Analyzer) -> None:
        """Register an analyzer instance."""
        identifier = analyzer.metadata.id
        if identifier in self._analyzers:
            msg = f"Analyzer '{identifier}' is already registered."
            raise ValueError(msg)
        self._analyzers[identifier] = analyzer
        logger.info("Registered analyzer '%s'", identifier)

    def unregister(self, analyzer_id: str) -> None:
        """Remove an analyzer from the registry."""
        if analyzer_id not in self._analyzers:
            msg = f"Analyzer '{analyzer_id}' not found."
            raise AnalyzerNotFoundError(msg)
        del self._analyzers[analyzer_id]
        logger.info("Unregistered analyzer '%s'", analyzer_id)

    def get(self, analyzer_id: str) -> Analyzer:
        """Return a registered analyzer by ID."""
        analyzer = self._analyzers.get(analyzer_id)
        if analyzer is None:
            msg = f"Analyzer '{analyzer_id}' not found."
            raise AnalyzerNotFoundError(msg)
        return analyzer

    def find(self, analyzer_id: str) -> Analyzer | None:
        """Return an analyzer when present, otherwise ``None``."""
        return self._analyzers.get(analyzer_id)

    def list_analyzers(self) -> list[str]:
        """Return registered analyzer identifiers."""
        return sorted(self._analyzers.keys())

    def list_instances(self) -> list[Analyzer]:
        """Return all registered analyzer instances."""
        return list(self._analyzers.values())

    def clear(self) -> None:
        """Remove all registered analyzers."""
        self._analyzers.clear()


analyzer_registry = AnalyzerRegistry()
