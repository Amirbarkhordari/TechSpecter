"""Monitoring service artifact analyzer."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.typed_base import TypedArtifactAnalyzer
from techspecter.analysis.models.finding import FindingCategory


class MonitoringServiceAnalyzer(TypedArtifactAnalyzer):
    """Detect passive monitoring and error tracking service references."""

    artifact_types = ("sentry", "rollbar", "bugsnag")
    display_name = "Monitoring Service"
    finding_category = FindingCategory.INFORMATION

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="monitoring-service-analyzer",
            name="Monitoring Service Analyzer",
            version="1.0.0",
            description="Detects passive monitoring and error tracking references.",
            category=FindingCategory.INFORMATION.value,
        )
