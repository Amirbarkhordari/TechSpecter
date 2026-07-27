"""Tests for passive artifact analyzer implementations."""

from __future__ import annotations

import pytest

from techspecter.analysis.artifact.analyzers import (
    AnalyticsServiceAnalyzer,
    ApiKeyAnalyzer,
    AwsMetadataAnalyzer,
    AzureMetadataAnalyzer,
    CdnAnalyzer,
    FirebaseAnalyzer,
    GoogleCloudMetadataAnalyzer,
    GraphqlMetadataAnalyzer,
    JwtAnalyzer,
    MonitoringServiceAnalyzer,
    OAuthMetadataAnalyzer,
    OpenApiAnalyzer,
    OpenIdConnectAnalyzer,
    TechnologyExposureAnalyzer,
    ThirdPartyServiceAnalyzer,
)
from techspecter.models.discovery import DiscoveryResult, Target
from tests.artifact_fixtures import sample_discovery_with_artifacts

ARTIFACT_ANALYZERS = [
    ApiKeyAnalyzer(),
    JwtAnalyzer(),
    OAuthMetadataAnalyzer(),
    OpenIdConnectAnalyzer(),
    GraphqlMetadataAnalyzer(),
    OpenApiAnalyzer(),
    FirebaseAnalyzer(),
    AwsMetadataAnalyzer(),
    AzureMetadataAnalyzer(),
    GoogleCloudMetadataAnalyzer(),
    CdnAnalyzer(),
    ThirdPartyServiceAnalyzer(),
    AnalyticsServiceAnalyzer(),
    MonitoringServiceAnalyzer(),
    TechnologyExposureAnalyzer(),
]


@pytest.mark.parametrize("analyzer", ARTIFACT_ANALYZERS, ids=lambda item: item.metadata.id)
def test_artifact_analyzers_produce_findings(analyzer) -> None:
    """Every artifact analyzer should emit structured findings."""
    discovery = sample_discovery_with_artifacts()
    result = analyzer.run(discovery)
    assert result.analyzer_id == analyzer.metadata.id
    assert result.findings
    finding = result.findings[0]
    assert finding.analyzer == analyzer.metadata.id
    assert finding.metadata.get("source") == "passive-artifact"


def test_graphql_analyzer_detects_graphql() -> None:
    """GraphQL analyzer should report GraphQL indicators."""
    analyzer = GraphqlMetadataAnalyzer()
    result = analyzer.run(sample_discovery_with_artifacts())
    assert any("graphql" in finding.title.lower() for finding in result.findings)


def test_jwt_analyzer_detects_jwt() -> None:
    """JWT analyzer should report JWT indicators."""
    analyzer = JwtAnalyzer()
    result = analyzer.run(sample_discovery_with_artifacts())
    assert any(
        "jwt" in finding.title.lower() or "token" in finding.title.lower()
        for finding in result.findings
    )


def test_analyzers_handle_missing_observation() -> None:
    """Analyzers should handle missing artifact observation gracefully."""
    discovery = DiscoveryResult(
        target=Target(original_url="https://example.com", url="https://example.com/"),
    )
    analyzer = OpenApiAnalyzer()
    result = analyzer.run(discovery)
    assert result.errors
    assert not result.findings
