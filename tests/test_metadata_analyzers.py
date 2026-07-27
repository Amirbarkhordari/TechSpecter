"""Tests for passive metadata analyzer implementations."""

from __future__ import annotations

import pytest

from techspecter.analysis.metadata.analyzers import (
    AdsTxtAnalyzer,
    AlternateLinkAnalyzer,
    AppleAppSiteAssociationAnalyzer,
    ApplicationMetadataAnalyzer,
    AssetLinksAnalyzer,
    BrowserConfigAnalyzer,
    CanonicalLinkAnalyzer,
    FaviconAnalyzer,
    FrameworkMetadataAnalyzer,
    GeneratorMetaAnalyzer,
    HtmlCommentAnalyzer,
    HtmlMetadataAnalyzer,
    HumansTxtAnalyzer,
    LanguageAnalyzer,
    ManifestAnalyzer,
    OpenGraphAnalyzer,
    RobotsTxtAnalyzer,
    SecurityTxtAnalyzer,
    ServiceWorkerAnalyzer,
    SitemapAnalyzer,
    SourceMapAnalyzer,
    ThemeColorAnalyzer,
    TwitterCardAnalyzer,
    WebAppManifestAnalyzer,
)
from techspecter.models.discovery import DiscoveryResult, Target
from tests.metadata_fixtures import sample_discovery_with_metadata

METADATA_ANALYZERS = [
    RobotsTxtAnalyzer(),
    SitemapAnalyzer(),
    SecurityTxtAnalyzer(),
    ManifestAnalyzer(),
    WebAppManifestAnalyzer(),
    BrowserConfigAnalyzer(),
    HumansTxtAnalyzer(),
    AdsTxtAnalyzer(),
    AssetLinksAnalyzer(),
    AppleAppSiteAssociationAnalyzer(),
    HtmlMetadataAnalyzer(),
    HtmlCommentAnalyzer(),
    OpenGraphAnalyzer(),
    TwitterCardAnalyzer(),
    CanonicalLinkAnalyzer(),
    AlternateLinkAnalyzer(),
    GeneratorMetaAnalyzer(),
    ThemeColorAnalyzer(),
    ApplicationMetadataAnalyzer(),
    LanguageAnalyzer(),
    FaviconAnalyzer(),
    SourceMapAnalyzer(),
    ServiceWorkerAnalyzer(),
    FrameworkMetadataAnalyzer(),
]


@pytest.mark.parametrize("analyzer", METADATA_ANALYZERS, ids=lambda item: item.metadata.id)
def test_metadata_analyzers_produce_findings(analyzer) -> None:
    """Every metadata analyzer should emit structured findings."""
    discovery = sample_discovery_with_metadata()
    result = analyzer.run(discovery)
    assert result.analyzer_id == analyzer.metadata.id
    assert result.findings
    finding = result.findings[0]
    assert finding.analyzer == analyzer.metadata.id
    assert finding.metadata.get("source") == "passive-metadata"


def test_robots_analyzer_reports_robots_txt() -> None:
    """Robots analyzer should report robots.txt availability."""
    analyzer = RobotsTxtAnalyzer()
    result = analyzer.run(sample_discovery_with_metadata())
    assert any("robots.txt" in finding.title.lower() for finding in result.findings)


def test_opengraph_analyzer_reports_properties() -> None:
    """OpenGraph analyzer should report og properties."""
    analyzer = OpenGraphAnalyzer()
    result = analyzer.run(sample_discovery_with_metadata())
    assert len(result.findings) >= 2


def test_sourcemap_analyzer_reports_references() -> None:
    """SourceMap analyzer should report passive references."""
    analyzer = SourceMapAnalyzer()
    result = analyzer.run(sample_discovery_with_metadata())
    assert any("sourcemap" in finding.id for finding in result.findings)


def test_analyzers_handle_missing_metadata() -> None:
    """Analyzers should fail gracefully when metadata is unavailable."""
    discovery = DiscoveryResult(
        target=Target(original_url="https://example.com", url="https://example.com/"),
    )
    result = HtmlMetadataAnalyzer().run(discovery)
    assert result.findings == []
    assert result.errors
