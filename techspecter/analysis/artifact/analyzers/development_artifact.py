"""Development artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.category_base import CategoryArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory, Severity


class DevelopmentArtifactAnalyzer(CategoryArtifactAnalyzer):
    """Detect passive development server and hot reload indicators."""

    categories = ("development",)
    display_name = "Development"
    finding_category = FindingCategory.INFORMATION
    default_severity = Severity.LOW

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="development-artifact-analyzer",
            name="Development Artifact Analyzer",
            version="1.0.0",
            description="Detects passive development server and HMR references.",
            category=FindingCategory.INFORMATION.value,
        )
