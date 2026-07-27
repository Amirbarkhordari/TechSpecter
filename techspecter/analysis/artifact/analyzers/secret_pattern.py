"""Secret pattern artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.category_base import CategoryArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory, Severity


class SecretPatternAnalyzer(CategoryArtifactAnalyzer):
    """Detect passive secret patterns in collected data."""

    categories = ("secret",)
    display_name = "Secret Pattern"
    finding_category = FindingCategory.SENSITIVE_ARTIFACT
    default_severity = Severity.HIGH
    default_confidence = 90.0
    recommendation = (
        "Review exposed secret patterns in public content. "
        "Never embed credentials in client-side assets."
    )

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="secret-pattern-analyzer",
            name="Secret Pattern Analyzer",
            version="1.0.0",
            description="Detects passive secret patterns without verification.",
            category=FindingCategory.SENSITIVE_ARTIFACT.value,
        )
