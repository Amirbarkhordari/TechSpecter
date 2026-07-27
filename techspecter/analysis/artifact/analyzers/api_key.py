"""API key artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.typed_base import TypedArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory, Severity


class ApiKeyAnalyzer(TypedArtifactAnalyzer):
    """Detect passive API key references in collected data."""

    artifact_types = ("api-key",)
    display_name = "API Key"
    default_severity = Severity.MEDIUM
    default_confidence = 85.0
    recommendation = (
        "Review API key references in client-side code. Never expose secrets in public assets."
    )

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="api-key-analyzer",
            name="API Key Analyzer",
            version="1.0.0",
            description="Detects passive API key references without verification.",
            category=FindingCategory.SENSITIVE_ARTIFACT.value,
        )
