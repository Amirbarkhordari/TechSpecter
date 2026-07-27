"""Apple App Site Association analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.metadata.analyzers.well_known_base import WellKnownResourceAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class AppleAppSiteAssociationAnalyzer(WellKnownResourceAnalyzer):
    """Analyze apple-app-site-association passive observations."""

    resource_type = "apple-app-site-association"
    display_name = "apple-app-site-association"

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="apple-app-site-association-analyzer",
            name="Apple App Site Association Analyzer",
            version="1.0.0",
            description="Analyzes passively collected apple-app-site-association resources.",
            category=FindingCategory.METADATA.value,
        )
