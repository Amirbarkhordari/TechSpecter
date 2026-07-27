"""Risk classification artifact analyzer."""

from __future__ import annotations

from collections import Counter

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.artifact.analyzers.base import PassiveArtifactAnalyzer
from techspecter.analysis.artifact.helpers import build_artifact_finding
from techspecter.analysis.artifact.risk import RiskEngine, RiskLevel
from techspecter.analysis.models.finding import FindingCategory, Severity
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.artifact import ArtifactDiscoveryObservation


class RiskClassificationAnalyzer(PassiveArtifactAnalyzer):
    """Prioritize artifact references by passive risk level."""

    def __init__(self, risk_engine: RiskEngine | None = None) -> None:
        """Initialize with optional risk engine."""
        self._risk_engine = risk_engine or RiskEngine()

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="risk-classification-analyzer",
            name="Risk Classification Analyzer",
            version="1.0.0",
            description="Assigns passive risk levels to artifact references.",
            category=FindingCategory.INFORMATION.value,
        )

    def analyze_artifacts(self, observation: ArtifactDiscoveryObservation) -> AnalyzerResult:
        """Produce risk classification findings."""
        if not observation.references:
            return AnalyzerResult(
                analyzer_id=self.metadata.id,
                findings=[
                    build_artifact_finding(
                        finding_id=f"{self.metadata.id}:none",
                        analyzer_id=self.metadata.id,
                        category=FindingCategory.INFORMATION,
                        title="No artifacts to prioritize",
                        description=(
                            "No passive artifact references were available for risk scoring."
                        ),
                    ),
                ],
            )

        assessments = self._risk_engine.assess_all(observation.references)
        risk_counts = Counter(assessment.risk_level.value for assessment in assessments)
        findings = []

        for index, assessment in enumerate(assessments, start=1):
            if assessment.risk_level in {RiskLevel.INFO, RiskLevel.LOW}:
                continue
            findings.append(
                build_artifact_finding(
                    finding_id=f"{self.metadata.id}:{assessment.artifact_type}:{index}",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.SENSITIVE_ARTIFACT,
                    title=(
                        f"Risk classified: {assessment.artifact_type} "
                        f"({assessment.risk_level.value})"
                    ),
                    description=(
                        f"Passive {assessment.artifact_type} reference classified as "
                        f"{assessment.classification.value} with "
                        f"{assessment.risk_level.value} risk."
                    ),
                    severity=assessment.severity,
                    confidence=assessment.confidence,
                    recommendation=assessment.recommendation,
                    metadata={
                        "classification": assessment.classification.value,
                        "risk_level": assessment.risk_level.value,
                        "artifact_type": assessment.artifact_type,
                    },
                ),
            )

        if not findings:
            findings.append(
                build_artifact_finding(
                    finding_id=f"{self.metadata.id}:low-risk",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.INFORMATION,
                    title="All artifacts classified as low or informational risk",
                    description="No medium or high passive risk artifacts were identified.",
                    severity=Severity.INFO,
                ),
            )

        findings.append(
            build_artifact_finding(
                finding_id=f"{self.metadata.id}:summary",
                analyzer_id=self.metadata.id,
                category=FindingCategory.INFORMATION,
                title="Risk classification summary",
                description=f"Prioritized {len(assessments)} artifact reference(s).",
                metadata={"risk_counts": dict(sorted(risk_counts.items()))},
            ),
        )
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
