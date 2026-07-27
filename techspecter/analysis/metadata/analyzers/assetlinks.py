"""AssetLinks analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.metadata.analyzers.well_known_base import WellKnownResourceAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class AssetLinksAnalyzer(WellKnownResourceAnalyzer):
    """Analyze assetlinks.json passive observations."""

    resource_type = "assetlinks.json"
    display_name = "assetlinks.json"

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="assetlinks-analyzer",
            name="AssetLinks Analyzer",
            version="1.0.0",
            description="Analyzes passively collected assetlinks.json resources.",
            category=FindingCategory.METADATA.value,
        )
