"""OpenAPI artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.typed_base import TypedArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class OpenApiAnalyzer(TypedArtifactAnalyzer):
    """Detect passive OpenAPI and Swagger metadata indicators."""

    artifact_types = (
        "openapi",
        "swagger",
        "swagger-ui",
        "redoc",
        "rest-api-version",
        "api-documentation",
    )
    display_name = "OpenAPI"
    finding_category = FindingCategory.ENDPOINT

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="openapi-analyzer",
            name="OpenAPI Analyzer",
            version="1.0.0",
            description="Detects passive OpenAPI, Swagger, and API documentation references.",
            category=FindingCategory.ENDPOINT.value,
        )
