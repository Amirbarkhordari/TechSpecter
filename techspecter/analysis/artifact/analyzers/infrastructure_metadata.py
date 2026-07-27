"""Infrastructure metadata artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.category_base import CategoryArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class InfrastructureMetadataAnalyzer(CategoryArtifactAnalyzer):
    """Detect passive infrastructure metadata references."""

    categories = ("infrastructure",)
    display_name = "Infrastructure Metadata"
    finding_category = FindingCategory.INFRASTRUCTURE

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="infrastructure-metadata-analyzer",
            name="Infrastructure Metadata Analyzer",
            version="1.0.0",
            description="Detects passive Docker, Kubernetes, and Terraform references.",
            category=FindingCategory.INFRASTRUCTURE.value,
        )
