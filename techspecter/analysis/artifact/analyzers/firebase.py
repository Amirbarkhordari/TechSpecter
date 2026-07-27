"""Firebase artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.typed_base import TypedArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class FirebaseAnalyzer(TypedArtifactAnalyzer):
    """Detect passive Firebase metadata indicators."""

    artifact_types = ("firebase",)
    display_name = "Firebase"
    finding_category = FindingCategory.INFRASTRUCTURE

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="firebase-analyzer",
            name="Firebase Analyzer",
            version="1.0.0",
            description="Detects passive Firebase configuration and hosting references.",
            category=FindingCategory.INFRASTRUCTURE.value,
        )
