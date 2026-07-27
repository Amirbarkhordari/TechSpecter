"""Tests for finding, severity, and confidence models."""

from __future__ import annotations

import pytest

from techspecter.analysis.models.confidence import clamp_confidence, normalize_confidence
from techspecter.analysis.models.finding import FindingCategory, Severity
from tests.analysis_fixtures import sample_finding


def test_finding_required_fields() -> None:
    """Verify finding stores all required fields."""
    finding = sample_finding(
        recommendation="Review the identified artifact.",
        metadata={"source": "test"},
    )
    assert finding.id == "finding-1"
    assert finding.analyzer == "test-analyzer"
    assert finding.category == FindingCategory.INFORMATION
    assert finding.severity == Severity.INFO
    assert finding.confidence == 75.0
    assert finding.recommendation == "Review the identified artifact."


def test_severity_values() -> None:
    """Verify severity enum values."""
    assert Severity.CRITICAL.value == "CRITICAL"
    assert Severity.HIGH.value == "HIGH"
    assert Severity.MEDIUM.value == "MEDIUM"
    assert Severity.LOW.value == "LOW"
    assert Severity.INFO.value == "INFO"


def test_finding_categories() -> None:
    """Verify standard finding categories exist."""
    assert FindingCategory.TECHNOLOGY.value == "Technology"
    assert FindingCategory.HTTP.value == "HTTP"
    assert FindingCategory.SENSITIVE_ARTIFACT.value == "Sensitive Artifact"
    assert FindingCategory.CUSTOM.value == "Custom"


def test_confidence_clamping() -> None:
    """Verify confidence scores are clamped to 0–100."""
    assert clamp_confidence(-5.0) == 0.0
    assert clamp_confidence(150.0) == 100.0
    assert normalize_confidence(88.888) == 88.89


def test_finding_confidence_bounds() -> None:
    """Verify finding confidence validation."""
    with pytest.raises(ValueError):
        sample_finding(confidence=101.0)
