"""High-level analysis service."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from techspecter.analysis.pipeline.pipeline import AnalysisPipeline
from techspecter.analysis.results.analysis_result import AnalysisResult
from techspecter.fingerprinting.models import DetectionResult, FingerprintAnalysisResult
from techspecter.models.discovery import DiscoveryResult

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class AnalysisService:
    """Public API for passive web application analysis."""

    pipeline: AnalysisPipeline | None = None

    async def run(self, target: str) -> AnalysisResult:
        """Analyze a target URL and return aggregated findings."""
        return await self.analyze_url(target)

    async def analyze_url(self, target_url: str) -> AnalysisResult:
        """Discover and analyze publicly accessible resources for a target URL."""
        return await self._pipeline().run(target_url)

    def analyze_discovery(self, discovery: DiscoveryResult) -> AnalysisResult:
        """Run analyzers against an existing discovery result."""
        return self._pipeline().analyze_discovery(discovery)

    def to_fingerprint_analysis_result(self, result: AnalysisResult) -> FingerprintAnalysisResult:
        """Convert an analysis result to the legacy fingerprint result model."""
        if result.detection is None:
            msg = "Analysis result does not contain fingerprint detection output."
            raise ValueError(msg)
        return FingerprintAnalysisResult(
            target_url=result.target_url,
            discovery_elapsed_ms=result.metadata.discovery_elapsed_ms,
            detection=result.detection,
            elapsed_ms=result.elapsed_ms,
        )

    def detection_from_analysis(self, result: AnalysisResult) -> DetectionResult:
        """Return the fingerprint detection portion of an analysis result."""
        if result.detection is None:
            msg = "Analysis result does not contain fingerprint detection output."
            raise ValueError(msg)
        return result.detection

    def _pipeline(self) -> AnalysisPipeline:
        """Return the configured analysis pipeline."""
        if self.pipeline is None:
            self.pipeline = AnalysisPipeline()
        return self.pipeline
