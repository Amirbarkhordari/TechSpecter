"""OAuth metadata artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.typed_base import TypedArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class OAuthMetadataAnalyzer(TypedArtifactAnalyzer):
    """Detect passive OAuth metadata indicators."""

    artifact_types = ("oauth", "authorization-endpoint", "token-endpoint")
    display_name = "OAuth"
    finding_category = FindingCategory.INFRASTRUCTURE

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="oauth-metadata-analyzer",
            name="OAuth Metadata Analyzer",
            version="1.0.0",
            description="Detects passive OAuth metadata and endpoint references.",
            category=FindingCategory.INFRASTRUCTURE.value,
        )
