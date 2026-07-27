"""Backup artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.category_base import CategoryArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory, Severity


class BackupArtifactAnalyzer(CategoryArtifactAnalyzer):
    """Detect passive backup and temporary file references."""

    categories = ("backup",)
    display_name = "Backup"
    finding_category = FindingCategory.SENSITIVE_ARTIFACT
    default_severity = Severity.LOW

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="backup-artifact-analyzer",
            name="Backup Artifact Analyzer",
            version="1.0.0",
            description="Detects passive backup, archive, and temporary file references.",
            category=FindingCategory.SENSITIVE_ARTIFACT.value,
        )
