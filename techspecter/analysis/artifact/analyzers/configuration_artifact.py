"""Configuration artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.category_base import CategoryArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory, Severity


class ConfigurationArtifactAnalyzer(CategoryArtifactAnalyzer):
    """Detect passive configuration artifact references."""

    categories = ("configuration",)
    display_name = "Configuration"
    finding_category = FindingCategory.CONFIGURATION
    default_severity = Severity.LOW

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="configuration-artifact-analyzer",
            name="Configuration Artifact Analyzer",
            version="1.0.0",
            description="Detects passive configuration file and object references.",
            category=FindingCategory.CONFIGURATION.value,
        )
