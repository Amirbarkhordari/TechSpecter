"""Environment artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.category_base import CategoryArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory, Severity


class EnvironmentArtifactAnalyzer(CategoryArtifactAnalyzer):
    """Detect passive environment variable and dotenv references."""

    categories = ("environment",)
    display_name = "Environment"
    finding_category = FindingCategory.CONFIGURATION
    default_severity = Severity.LOW

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="environment-artifact-analyzer",
            name="Environment Artifact Analyzer",
            version="1.0.0",
            description="Detects passive environment and dotenv references.",
            category=FindingCategory.CONFIGURATION.value,
        )
