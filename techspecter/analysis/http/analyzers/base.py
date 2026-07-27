"""Base class for passive HTTP analyzers."""

from __future__ import annotations

from abc import abstractmethod

from techspecter.analysis.analyzers.base import Analyzer
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.discovery import DiscoveryResult
from techspecter.models.http import HttpResponseObservation


class PassiveHttpAnalyzer(Analyzer):
    """Base analyzer for passive HTTP response inspection."""

    @abstractmethod
    def analyze_http(self, observation: HttpResponseObservation) -> AnalyzerResult:
        """Analyze HTTP observation data."""

    def execute(self, discovery: DiscoveryResult) -> AnalyzerResult:
        """Run passive HTTP analysis when observation data exists."""
        observation = discovery.http_response
        if observation is None:
            return AnalyzerResult(
                analyzer_id=self.metadata.id,
                findings=[],
                errors=["No HTTP response observation available."],
            )
        return self.analyze_http(observation)
