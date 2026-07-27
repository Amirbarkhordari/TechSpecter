"""Azure metadata artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.typed_base import TypedArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class AzureMetadataAnalyzer(TypedArtifactAnalyzer):
    """Detect passive Azure cloud metadata indicators."""

    artifact_types = ("azure", "blob-storage")
    display_name = "Azure"
    finding_category = FindingCategory.INFRASTRUCTURE

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="azure-metadata-analyzer",
            name="Azure Metadata Analyzer",
            version="1.0.0",
            description="Detects passive Azure and blob storage references.",
            category=FindingCategory.INFRASTRUCTURE.value,
        )
