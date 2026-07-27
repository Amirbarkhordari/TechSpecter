"""Source artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.category_base import CategoryArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class SourceArtifactAnalyzer(CategoryArtifactAnalyzer):
    """Detect passive source map and source URL references."""

    categories = ("source",)
    display_name = "Source"
    finding_category = FindingCategory.METADATA

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="source-artifact-analyzer",
            name="Source Artifact Analyzer",
            version="1.0.0",
            description="Detects passive source map and source URL references.",
            category=FindingCategory.METADATA.value,
        )
