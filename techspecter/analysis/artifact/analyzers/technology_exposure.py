"""Technology exposure artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.typed_base import TypedArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class TechnologyExposureAnalyzer(TypedArtifactAnalyzer):
    """Detect passive technology exposure indicators."""

    artifact_types = ("technology-exposure", "public-key")
    display_name = "Technology Exposure"
    finding_category = FindingCategory.TECHNOLOGY

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="technology-exposure-analyzer",
            name="Technology Exposure Analyzer",
            version="1.0.0",
            description="Detects passive build tooling and public key exposure indicators.",
            category=FindingCategory.TECHNOLOGY.value,
        )
