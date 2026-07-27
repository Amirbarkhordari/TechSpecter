"""Sitemap analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.metadata.analyzers.well_known_base import WellKnownResourceAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class SitemapAnalyzer(WellKnownResourceAnalyzer):
    """Analyze sitemap passive observations."""

    resource_type = "sitemap.xml"
    display_name = "sitemap"

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="sitemap-analyzer",
            name="Sitemap Analyzer",
            version="1.0.0",
            description="Analyzes passively collected sitemap resources.",
            category=FindingCategory.METADATA.value,
        )
