"""Build artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.category_base import CategoryArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class BuildArtifactAnalyzer(CategoryArtifactAnalyzer):
    """Detect passive build toolchain and bundle metadata."""

    categories = ("build",)
    display_name = "Build"
    finding_category = FindingCategory.TECHNOLOGY

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="build-artifact-analyzer",
            name="Build Artifact Analyzer",
            version="1.0.0",
            description="Detects passive build toolchain and bundle metadata indicators.",
            category=FindingCategory.TECHNOLOGY.value,
        )
