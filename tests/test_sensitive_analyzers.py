"""Tests for sensitive artifact analyzers."""

from __future__ import annotations

import pytest

from techspecter.analysis.artifact.analyzers import (
    BackupArtifactAnalyzer,
    BuildArtifactAnalyzer,
    ClientConfigurationAnalyzer,
    ConfigurationArtifactAnalyzer,
    DebugArtifactAnalyzer,
    DevelopmentArtifactAnalyzer,
    EnvironmentArtifactAnalyzer,
    ExposureClassificationAnalyzer,
    InfrastructureMetadataAnalyzer,
    RiskClassificationAnalyzer,
    SecretPatternAnalyzer,
    SourceArtifactAnalyzer,
)
from techspecter.models.discovery import DiscoveryResult, Target
from tests.sensitive_fixtures import sample_discovery_with_sensitive_artifacts

SENSITIVE_ANALYZERS = [
    SecretPatternAnalyzer(),
    ConfigurationArtifactAnalyzer(),
    BuildArtifactAnalyzer(),
    DebugArtifactAnalyzer(),
    BackupArtifactAnalyzer(),
    EnvironmentArtifactAnalyzer(),
    SourceArtifactAnalyzer(),
    ClientConfigurationAnalyzer(),
    DevelopmentArtifactAnalyzer(),
    InfrastructureMetadataAnalyzer(),
    ExposureClassificationAnalyzer(),
    RiskClassificationAnalyzer(),
]


@pytest.mark.parametrize("analyzer", SENSITIVE_ANALYZERS, ids=lambda item: item.metadata.id)
def test_sensitive_analyzers_produce_findings(analyzer) -> None:
    """Every sensitive artifact analyzer should emit structured findings."""
    discovery = sample_discovery_with_sensitive_artifacts()
    result = analyzer.run(discovery)
    assert result.analyzer_id == analyzer.metadata.id
    assert result.findings
    assert result.findings[0].metadata.get("source") == "passive-artifact"


def test_secret_pattern_analyzer_detects_secrets() -> None:
    """Secret pattern analyzer should report secret indicators."""
    analyzer = SecretPatternAnalyzer()
    result = analyzer.run(sample_discovery_with_sensitive_artifacts())
    assert any("secret" in finding.title.lower() for finding in result.findings)


def test_exposure_classification_summarizes_categories() -> None:
    """Exposure classification analyzer should produce category summary."""
    analyzer = ExposureClassificationAnalyzer()
    result = analyzer.run(sample_discovery_with_sensitive_artifacts())
    assert any("summary" in finding.id for finding in result.findings)


def test_analyzers_handle_missing_observation() -> None:
    """Analyzers should handle missing artifact observation gracefully."""
    discovery = DiscoveryResult(
        target=Target(original_url="https://example.com", url="https://example.com/"),
    )
    result = SecretPatternAnalyzer().run(discovery)
    assert result.errors
