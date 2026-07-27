"""JWT artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.typed_base import TypedArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory, Severity


class JwtAnalyzer(TypedArtifactAnalyzer):
    """Detect passive JWT token references in collected data."""

    artifact_types = ("jwt", "bearer-token")
    display_name = "JWT/Token"
    default_severity = Severity.MEDIUM
    default_confidence = 88.0
    recommendation = (
        "Review token references in client-side assets. "
        "Tokens should not be embedded in public code."
    )

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="jwt-analyzer",
            name="JWT Analyzer",
            version="1.0.0",
            description="Detects passive JWT and bearer token references without verification.",
            category=FindingCategory.SENSITIVE_ARTIFACT.value,
        )
