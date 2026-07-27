"""BrowserConfig analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.metadata.analyzers.well_known_base import WellKnownResourceAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class BrowserConfigAnalyzer(WellKnownResourceAnalyzer):
    """Analyze browserconfig.xml passive observations."""

    resource_type = "browserconfig.xml"
    display_name = "browserconfig.xml"

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="browserconfig-analyzer",
            name="BrowserConfig Analyzer",
            version="1.0.0",
            description="Analyzes passively collected browserconfig.xml resources.",
            category=FindingCategory.METADATA.value,
        )
