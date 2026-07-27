"""Passive artifact risk prioritization engine."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from techspecter.analysis.artifact.classification import (
    ArtifactClassification,
    ClassificationEngine,
)
from techspecter.analysis.models.finding import Severity
from techspecter.models.artifact import ArtifactReference


class RiskLevel(StrEnum):
    """Passive risk level assignments (not CVSS)."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """Passive risk assessment for an artifact reference."""

    classification: ArtifactClassification
    artifact_type: str
    severity: Severity
    confidence: float
    risk_level: RiskLevel
    recommendation: str


_SECRET_TYPES = frozenset(
    {
        "aws-access-key",
        "google-api-key",
        "firebase-key",
        "stripe-secret-key",
        "github-token",
        "gitlab-token",
        "slack-token",
        "discord-token",
        "twilio-key",
        "sendgrid-key",
        "azure-key",
        "webhook-token",
        "private-key-header",
        "high-entropy-token",
    }
)

_HIGH_RISK_TYPES = frozenset(
    {
        "jwt-token",
        "bearer-token-ref",
        "basic-auth-token",
        "pem-block",
        "certificate-block",
        "public-ssh-key",
        "debug-endpoint",
        "stack-trace",
        "backup-filename",
        "deployment-leftover",
    }
)


class RiskEngine:
    """Assign passive severity, confidence, and risk level to artifact references."""

    def __init__(self, classifier: ClassificationEngine | None = None) -> None:
        """Initialize with optional classification engine."""
        self._classifier = classifier or ClassificationEngine()

    def assess(self, reference: ArtifactReference) -> RiskAssessment:
        """Produce a passive risk assessment without validation or exploitation claims."""
        classification = self._classifier.classify(reference)
        severity, risk_level, confidence = self._score(reference, classification)
        return RiskAssessment(
            classification=classification,
            artifact_type=reference.artifact_type,
            severity=severity,
            confidence=confidence,
            risk_level=risk_level,
            recommendation=self._recommendation(classification, reference.artifact_type),
        )

    def assess_all(self, references: list[ArtifactReference]) -> list[RiskAssessment]:
        """Assess risk for all artifact references."""
        return [self.assess(reference) for reference in references]

    def _score(
        self,
        reference: ArtifactReference,
        classification: ArtifactClassification,
    ) -> tuple[Severity, RiskLevel, float]:
        """Compute passive severity, risk level, and confidence."""
        artifact_type = reference.artifact_type
        if artifact_type in _SECRET_TYPES:
            return Severity.HIGH, RiskLevel.HIGH, 92.0
        if artifact_type in _HIGH_RISK_TYPES:
            return Severity.MEDIUM, RiskLevel.MEDIUM, 85.0
        if classification == ArtifactClassification.SECRETS:
            return Severity.HIGH, RiskLevel.HIGH, 88.0
        if classification == ArtifactClassification.AUTHENTICATION:
            return Severity.MEDIUM, RiskLevel.MEDIUM, 82.0
        if classification == ArtifactClassification.DEBUG:
            return Severity.MEDIUM, RiskLevel.MEDIUM, 78.0
        if classification == ArtifactClassification.BACKUP:
            return Severity.LOW, RiskLevel.LOW, 75.0
        if classification == ArtifactClassification.CONFIGURATION:
            return Severity.LOW, RiskLevel.LOW, 80.0
        if classification == ArtifactClassification.BUILD:
            return Severity.INFO, RiskLevel.INFO, 85.0
        if classification == ArtifactClassification.DEVELOPMENT:
            return Severity.LOW, RiskLevel.LOW, 70.0
        return Severity.INFO, RiskLevel.INFO, 75.0

    def _recommendation(
        self,
        classification: ArtifactClassification,
        artifact_type: str,
    ) -> str:
        """Return a passive recommendation without exploitation claims."""
        if classification in {
            ArtifactClassification.SECRETS,
            ArtifactClassification.AUTHENTICATION,
        }:
            return (
                "Review exposed credential patterns in public content. "
                "Remove secrets from client-side assets and rotate if unintentionally exposed."
            )
        if classification == ArtifactClassification.CONFIGURATION:
            return (
                "Review public configuration references and limit exposure to non-sensitive values."
            )
        if classification == ArtifactClassification.DEBUG:
            return "Remove debug indicators from production-facing assets."
        if classification == ArtifactClassification.BACKUP:
            return "Review backup and temporary file references exposed in public content."
        return f"Review passive {artifact_type} indicator and confirm intentional public exposure."
