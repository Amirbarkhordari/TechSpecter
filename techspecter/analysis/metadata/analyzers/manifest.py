"""Manifest analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.metadata.analyzers.well_known_base import WellKnownResourceAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class ManifestAnalyzer(WellKnownResourceAnalyzer):
    """Analyze manifest.json passive observations."""

    resource_type = "manifest.json"
    display_name = "manifest.json"

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="manifest-analyzer",
            name="Manifest Analyzer",
            version="1.0.0",
            description="Analyzes passively collected manifest.json resources.",
            category=FindingCategory.METADATA.value,
        )
