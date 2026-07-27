"""Base class for passive artifact analyzers."""

from __future__ import annotations

from abc import abstractmethod

from techspecter.analysis.analyzers.base import Analyzer
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.artifact import ArtifactDiscoveryObservation
from techspecter.models.discovery import DiscoveryResult


class PassiveArtifactAnalyzer(Analyzer):
    """Base analyzer for passive artifact inspection."""

    @abstractmethod
    def analyze_artifacts(self, observation: ArtifactDiscoveryObservation) -> AnalyzerResult:
        """Analyze artifact observation data."""

    def execute(self, discovery: DiscoveryResult) -> AnalyzerResult:
        """Run passive artifact analysis when observation data exists."""
        observation = discovery.artifact_observation
        if observation is None:
            return AnalyzerResult(
                analyzer_id=self.metadata.id,
                findings=[],
                errors=["No artifact observation available."],
            )
        return self.analyze_artifacts(observation)
