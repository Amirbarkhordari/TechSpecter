"""Google Cloud metadata artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.typed_base import TypedArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class GoogleCloudMetadataAnalyzer(TypedArtifactAnalyzer):
    """Detect passive Google Cloud metadata indicators."""

    artifact_types = ("gcp",)
    display_name = "Google Cloud"
    finding_category = FindingCategory.INFRASTRUCTURE

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="google-cloud-metadata-analyzer",
            name="Google Cloud Metadata Analyzer",
            version="1.0.0",
            description="Detects passive Google Cloud Platform references.",
            category=FindingCategory.INFRASTRUCTURE.value,
        )
