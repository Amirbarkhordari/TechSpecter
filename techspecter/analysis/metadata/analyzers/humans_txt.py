"""Humans.txt analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.metadata.analyzers.well_known_base import WellKnownResourceAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class HumansTxtAnalyzer(WellKnownResourceAnalyzer):
    """Analyze humans.txt passive observations."""

    resource_type = "humans.txt"
    display_name = "humans.txt"

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="humans-txt-analyzer",
            name="Humans.txt Analyzer",
            version="1.0.0",
            description="Analyzes passively collected humans.txt resources.",
            category=FindingCategory.METADATA.value,
        )
