"""Robots.txt analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.metadata.analyzers.well_known_base import WellKnownResourceAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class RobotsTxtAnalyzer(WellKnownResourceAnalyzer):
    """Analyze robots.txt passive observations."""

    resource_type = "robots.txt"
    display_name = "robots.txt"

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="robots-analyzer",
            name="Robots.txt Analyzer",
            version="1.0.0",
            description="Analyzes passively collected robots.txt resources.",
            category=FindingCategory.METADATA.value,
        )
