"""Analytics service artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.typed_base import TypedArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class AnalyticsServiceAnalyzer(TypedArtifactAnalyzer):
    """Detect passive analytics service integration references."""

    artifact_types = ("google-analytics", "google-tag-manager", "matomo")
    display_name = "Analytics Service"
    finding_category = FindingCategory.INFORMATION

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="analytics-service-analyzer",
            name="Analytics Service Analyzer",
            version="1.0.0",
            description="Detects passive analytics and tag manager references.",
            category=FindingCategory.INFORMATION.value,
        )
