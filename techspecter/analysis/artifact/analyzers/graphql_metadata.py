"""GraphQL metadata artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.typed_base import TypedArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class GraphqlMetadataAnalyzer(TypedArtifactAnalyzer):
    """Detect passive GraphQL metadata indicators."""

    artifact_types = ("graphql", "graphql-playground", "graphql-voyager", "apollo")
    display_name = "GraphQL"
    finding_category = FindingCategory.ENDPOINT

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="graphql-metadata-analyzer",
            name="GraphQL Metadata Analyzer",
            version="1.0.0",
            description="Detects passive GraphQL endpoints and playground references.",
            category=FindingCategory.ENDPOINT.value,
        )
