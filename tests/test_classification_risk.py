"""Tests for classification and risk engines."""

from __future__ import annotations

from techspecter.analysis.artifact.classification import (
    ArtifactClassification,
    ClassificationEngine,
)
from techspecter.analysis.artifact.risk import RiskEngine, RiskLevel
from techspecter.models.artifact import ArtifactReference


def test_classification_engine_classifies_secrets() -> None:
    """Classification engine should map secret types to Secrets bucket."""
    reference = ArtifactReference(
        artifact_type="aws-access-key",
        category="secret",
        value="redacted",
        source="inline-script",
    )
    assert ClassificationEngine().classify(reference) == ArtifactClassification.SECRETS


def test_risk_engine_assigns_high_risk_to_secrets() -> None:
    """Risk engine should assign high risk to secret patterns."""
    reference = ArtifactReference(
        artifact_type="aws-access-key",
        category="secret",
        value="redacted",
        source="inline-script",
    )
    assessment = RiskEngine().assess(reference)
    assert assessment.risk_level == RiskLevel.HIGH
    assert assessment.classification == ArtifactClassification.SECRETS
    assert assessment.confidence >= 85.0
