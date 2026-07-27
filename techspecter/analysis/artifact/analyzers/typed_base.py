"""Shared base for typed artifact analyzers."""

from __future__ import annotations

from abc import abstractmethod

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.base import PassiveArtifactAnalyzer
from techspecter.analysis.artifact.helpers import build_artifact_finding, finding_from_reference
from techspecter.analysis.models.finding import FindingCategory, Severity
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.artifact import ArtifactDiscoveryObservation


class TypedArtifactAnalyzer(PassiveArtifactAnalyzer):
    """Analyze artifact references filtered by artifact type."""

    artifact_types: tuple[str, ...] = ()
    display_name: str = "Artifact"
    finding_category: FindingCategory | str = FindingCategory.SENSITIVE_ARTIFACT
    default_severity: Severity = Severity.INFO
    default_confidence: float = 90.0
    recommendation: str | None = (
        "Review exposed artifact indicators and ensure only intentional public metadata is present."
    )

    @property
    @abstractmethod
    def metadata(self) -> AnalyzerMetadata:
        """Return analyzer metadata."""

    def analyze_artifacts(self, observation: ArtifactDiscoveryObservation) -> AnalyzerResult:
        """Analyze matching artifact references."""
        matches = observation.references_for_types(*self.artifact_types)
        if not matches:
            return AnalyzerResult(
                analyzer_id=self.metadata.id,
                findings=[
                    build_artifact_finding(
                        finding_id=f"{self.metadata.id}:none",
                        analyzer_id=self.metadata.id,
                        category=self.finding_category,
                        title=f"No {self.display_name} indicators observed",
                        description=(
                            f"No passive {self.display_name.lower()} indicators were detected."
                        ),
                    ),
                ],
            )

        findings = [
            finding_from_reference(
                analyzer_id=self.metadata.id,
                reference=reference,
                index=index,
                title_prefix=f"{self.display_name} indicator",
                recommendation=self.recommendation,
                severity=self.default_severity,
                confidence=self.default_confidence,
                category=self.finding_category,
            )
            for index, reference in enumerate(matches, start=1)
        ]
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
