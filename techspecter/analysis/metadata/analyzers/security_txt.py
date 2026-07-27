"""Security.txt analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.metadata.analyzers.well_known_base import WellKnownResourceAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class SecurityTxtAnalyzer(WellKnownResourceAnalyzer):
    """Analyze security.txt passive observations."""

    resource_type = "security.txt"
    display_name = "security.txt"

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="security-txt-analyzer",
            name="Security.txt Analyzer",
            version="1.0.0",
            description="Analyzes passively collected security.txt resources.",
            category=FindingCategory.METADATA.value,
        )
