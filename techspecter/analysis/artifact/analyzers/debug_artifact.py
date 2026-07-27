"""Debug artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.category_base import CategoryArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory, Severity


class DebugArtifactAnalyzer(CategoryArtifactAnalyzer):
    """Detect passive debug and development mode indicators."""

    categories = ("debug",)
    display_name = "Debug"
    finding_category = FindingCategory.INFORMATION
    default_severity = Severity.MEDIUM

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="debug-artifact-analyzer",
            name="Debug Artifact Analyzer",
            version="1.0.0",
            description="Detects passive debug banners, endpoints, and stack trace fragments.",
            category=FindingCategory.INFORMATION.value,
        )
