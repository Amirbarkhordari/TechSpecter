"""Ads.txt analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.metadata.analyzers.well_known_base import WellKnownResourceAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class AdsTxtAnalyzer(WellKnownResourceAnalyzer):
    """Analyze ads.txt passive observations."""

    resource_type = "ads.txt"
    display_name = "ads.txt"

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="ads-txt-analyzer",
            name="Ads.txt Analyzer",
            version="1.0.0",
            description="Analyzes passively collected ads.txt resources.",
            category=FindingCategory.METADATA.value,
        )
