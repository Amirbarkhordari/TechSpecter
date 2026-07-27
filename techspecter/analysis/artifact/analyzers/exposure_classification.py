"""Exposure classification artifact analyzer."""

from __future__ import annotations

from collections import Counter

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.base import PassiveArtifactAnalyzer
from techspecter.analysis.artifact.classification import (
    ClassificationEngine,
)
from techspecter.analysis.artifact.helpers import build_artifact_finding
from techspecter.analysis.models.finding import FindingCategory, Severity
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.artifact import ArtifactDiscoveryObservation


class ExposureClassificationAnalyzer(PassiveArtifactAnalyzer):
    """Classify all artifact references into exposure categories."""

    def __init__(self, classifier: ClassificationEngine | None = None) -> None:
        """Initialize with optional classification engine."""
        self._classifier = classifier or ClassificationEngine()

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="exposure-classification-analyzer",
            name="Exposure Classification Analyzer",
            version="1.0.0",
            description="Classifies passive artifact references into exposure categories.",
            category=FindingCategory.INFORMATION.value,
        )

    def analyze_artifacts(self, observation: ArtifactDiscoveryObservation) -> AnalyzerResult:
        """Produce classification findings for observed artifact references."""
        if not observation.references:
            return AnalyzerResult(
                analyzer_id=self.metadata.id,
                findings=[
                    build_artifact_finding(
                        finding_id=f"{self.metadata.id}:none",
                        analyzer_id=self.metadata.id,
                        category=FindingCategory.INFORMATION,
                        title="No artifacts to classify",
                        description=(
                            "No passive artifact references were available for classification."
                        ),
                    ),
                ],
            )

        grouped = self._classifier.classify_all(observation.references)
        counts = Counter(
            self._classifier.classify(reference).value for reference in observation.references
        )
        findings = [
            build_artifact_finding(
                finding_id=f"{self.metadata.id}:{classification.value.lower()}",
                analyzer_id=self.metadata.id,
                category=FindingCategory.INFORMATION,
                title=f"Exposure classification: {classification.value}",
                description=(
                    f"{len(references)} passive artifact reference(s) classified as "
                    f"{classification.value}."
                ),
                severity=Severity.INFO,
                confidence=95.0,
                metadata={
                    "classification": classification.value,
                    "count": len(references),
                    "artifact_types": sorted({item.artifact_type for item in references}),
                },
            )
            for classification, references in sorted(
                grouped.items(),
                key=lambda item: item[0].value,
            )
        ]
        findings.append(
            build_artifact_finding(
                finding_id=f"{self.metadata.id}:summary",
                analyzer_id=self.metadata.id,
                category=FindingCategory.INFORMATION,
                title="Exposure classification summary",
                description=f"Classified {len(observation.references)} artifact reference(s).",
                metadata={"category_counts": dict(sorted(counts.items()))},
            ),
        )
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
