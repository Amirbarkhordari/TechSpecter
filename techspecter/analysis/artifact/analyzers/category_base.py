"""Category-based artifact analyzer base."""

from __future__ import annotations

from abc import abstractmethod

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.base import PassiveArtifactAnalyzer
from techspecter.analysis.artifact.helpers import build_artifact_finding, finding_from_reference
from techspecter.analysis.models.finding import FindingCategory, Severity
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.artifact import ArtifactDiscoveryObservation


class CategoryArtifactAnalyzer(PassiveArtifactAnalyzer):
    """Analyze artifact references filtered by category."""

    categories: tuple[str, ...] = ()
    display_name: str = "Artifact"
    finding_category: FindingCategory | str = FindingCategory.SENSITIVE_ARTIFACT
    default_severity: Severity = Severity.INFO
    default_confidence: float = 85.0
    recommendation: str | None = (
        "Review exposed artifact indicators and ensure only intentional public content is present."
    )

    @property
    @abstractmethod
    def metadata(self) -> AnalyzerMetadata:
        """Return analyzer metadata."""

    def analyze_artifacts(self, observation: ArtifactDiscoveryObservation) -> AnalyzerResult:
        """Analyze matching artifact references by category."""
        matches = [item for item in observation.references if item.category in self.categories]
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

        findings = []
        for index, reference in enumerate(matches, start=1):
            severity = self.default_severity
            confidence = self.default_confidence
            risk_meta = reference.metadata
            if "severity" in risk_meta:
                try:
                    severity = Severity(str(risk_meta["severity"]))
                except ValueError:
                    severity = self.default_severity
            if "confidence" in risk_meta:
                raw_confidence = risk_meta["confidence"]
                if isinstance(raw_confidence, (int, float)):
                    confidence = float(raw_confidence)

            findings.append(
                finding_from_reference(
                    analyzer_id=self.metadata.id,
                    reference=reference,
                    index=index,
                    title_prefix=f"{self.display_name} indicator",
                    recommendation=self.recommendation,
                    severity=severity,
                    confidence=confidence,
                    category=self.finding_category,
                )
            )
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)


class TypedCategoryArtifactAnalyzer(CategoryArtifactAnalyzer):
    """Analyze artifact references filtered by category and artifact types."""

    artifact_types: tuple[str, ...] = ()

    def analyze_artifacts(self, observation: ArtifactDiscoveryObservation) -> AnalyzerResult:
        """Analyze matching references by category and type."""
        allowed_types = set(self.artifact_types)
        matches = [
            item
            for item in observation.references
            if item.category in self.categories
            and (not allowed_types or item.artifact_type in allowed_types)
        ]
        filtered = observation.model_copy(update={"references": matches})
        if matches:
            return super().analyze_artifacts(filtered)
        return super().analyze_artifacts(observation.model_copy(update={"references": []}))
