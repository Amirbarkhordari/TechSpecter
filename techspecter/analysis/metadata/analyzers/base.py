"""Base class for passive metadata analyzers."""

from __future__ import annotations

from abc import abstractmethod

from techspecter.analysis.analyzers.base import Analyzer
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.discovery import DiscoveryResult
from techspecter.models.metadata import MetadataDiscoveryObservation


class PassiveMetadataAnalyzer(Analyzer):
    """Base analyzer for passive metadata inspection."""

    @abstractmethod
    def analyze_metadata(self, observation: MetadataDiscoveryObservation) -> AnalyzerResult:
        """Analyze metadata observation data."""

    def execute(self, discovery: DiscoveryResult) -> AnalyzerResult:
        """Run passive metadata analysis when observation data exists."""
        observation = discovery.metadata_observation
        if observation is None:
            return AnalyzerResult(
                analyzer_id=self.metadata.id,
                findings=[],
                errors=["No metadata observation available."],
            )
        return self.analyze_metadata(observation)
