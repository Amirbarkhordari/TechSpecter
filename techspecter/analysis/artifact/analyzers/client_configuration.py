"""Client configuration artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.category_base import CategoryArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory, Severity


class ClientConfigurationAnalyzer(CategoryArtifactAnalyzer):
    """Detect passive client-side configuration objects."""

    categories = ("client-config",)
    display_name = "Client Configuration"
    finding_category = FindingCategory.CONFIGURATION
    default_severity = Severity.LOW

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="client-configuration-analyzer",
            name="Client Configuration Analyzer",
            version="1.0.0",
            description="Detects passive window and client-side configuration objects.",
            category=FindingCategory.CONFIGURATION.value,
        )
