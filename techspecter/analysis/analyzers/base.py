"""Analyzer base classes and metadata."""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod

from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.base import TechSpecterModel
from techspecter.models.discovery import DiscoveryResult

logger = logging.getLogger(__name__)


class AnalyzerMetadata(TechSpecterModel):
    """Descriptive metadata for an analysis module."""

    id: str
    name: str
    version: str
    description: str
    category: str


class Analyzer(ABC):
    """Base class for passive web application analyzers."""

    @property
    @abstractmethod
    def metadata(self) -> AnalyzerMetadata:
        """Return analyzer metadata."""

    @abstractmethod
    def execute(self, discovery: DiscoveryResult) -> AnalyzerResult:
        """Analyze discovery output and return findings."""

    def run(self, discovery: DiscoveryResult) -> AnalyzerResult:
        """Execute the analyzer with timing and error handling."""
        started = time.perf_counter()
        try:
            result = self.execute(discovery)
        except Exception as exc:
            logger.exception(
                "Analyzer '%s' failed during execution",
                self.metadata.id,
            )
            elapsed_ms = (time.perf_counter() - started) * 1000
            return AnalyzerResult(
                analyzer_id=self.metadata.id,
                findings=[],
                elapsed_ms=elapsed_ms,
                errors=[str(exc)],
            )
        elapsed_ms = (time.perf_counter() - started) * 1000
        if result.elapsed_ms == 0.0:
            result = result.model_copy(update={"elapsed_ms": elapsed_ms})
        return result
