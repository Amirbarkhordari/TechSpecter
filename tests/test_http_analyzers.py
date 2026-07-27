"""Tests for passive HTTP analyzer implementations."""

from __future__ import annotations

import pytest

from techspecter.analysis.http.analyzers import (
    CacheControlAnalyzer,
    ContentTypeAnalyzer,
    CookieAnalyzer,
    CorsAnalyzer,
    CspAnalyzer,
    HttpHeaderAnalyzer,
    HttpResponseMetadataAnalyzer,
    RedirectAnalyzer,
    SecurityHeaderAnalyzer,
    ServerFingerprintAnalyzer,
)
from techspecter.analysis.http.constants import COMMON_RESPONSE_HEADERS, SECURITY_HEADERS
from techspecter.models.discovery import DiscoveryResult, Target
from tests.http_fixtures import sample_discovery_with_http, sample_http_observation

HTTP_ANALYZERS = [
    HttpHeaderAnalyzer(),
    SecurityHeaderAnalyzer(),
    CookieAnalyzer(),
    CspAnalyzer(),
    CorsAnalyzer(),
    CacheControlAnalyzer(),
    ContentTypeAnalyzer(),
    ServerFingerprintAnalyzer(),
    RedirectAnalyzer(),
    HttpResponseMetadataAnalyzer(),
]


@pytest.mark.parametrize("analyzer", HTTP_ANALYZERS, ids=lambda item: item.metadata.id)
def test_http_analyzers_produce_findings(analyzer) -> None:
    """Every HTTP analyzer should emit structured findings."""
    discovery = sample_discovery_with_http()
    result = analyzer.run(discovery)
    assert result.analyzer_id == analyzer.metadata.id
    assert result.findings
    finding = result.findings[0]
    assert finding.analyzer == analyzer.metadata.id
    assert finding.title
    assert finding.description
    assert finding.metadata.get("source") == "passive-http-response"


def test_http_header_analyzer_covers_common_headers() -> None:
    """Header analyzer should evaluate every common response header."""
    analyzer = HttpHeaderAnalyzer()
    result = analyzer.run(sample_discovery_with_http())
    assert len(result.findings) == len(COMMON_RESPONSE_HEADERS)


def test_security_header_analyzer_covers_security_headers() -> None:
    """Security header analyzer should evaluate every security header."""
    analyzer = SecurityHeaderAnalyzer()
    result = analyzer.run(sample_discovery_with_http())
    assert len(result.findings) == len(SECURITY_HEADERS)


def test_cookie_analyzer_reports_cookie_attributes() -> None:
    """Cookie analyzer should expose cookie attributes in metadata."""
    analyzer = CookieAnalyzer()
    result = analyzer.run(sample_discovery_with_http())
    cookie_finding = next(item for item in result.findings if item.id.startswith("cookie:session"))
    assert cookie_finding.metadata["secure"] is True
    assert cookie_finding.metadata["httponly"] is True


def test_redirect_analyzer_reports_redirect_hops() -> None:
    """Redirect analyzer should report redirect chain hops."""
    analyzer = RedirectAnalyzer()
    result = analyzer.run(sample_discovery_with_http())
    assert any(item.id.startswith("redirect:") for item in result.findings)


def test_analyzers_handle_missing_http_observation() -> None:
    """Analyzers should fail gracefully when HTTP data is unavailable."""
    discovery = DiscoveryResult(
        target=Target(original_url="https://example.com", url="https://example.com/"),
    )
    analyzer = HttpHeaderAnalyzer()
    result = analyzer.run(discovery)
    assert result.findings == []
    assert result.errors


def test_response_metadata_analyzer_reports_status_and_size() -> None:
    """Response metadata analyzer should report status code and body size."""
    analyzer = HttpResponseMetadataAnalyzer()
    observation = sample_http_observation(status_code=404, body_size=99)
    discovery = sample_discovery_with_http(http_response=observation)
    result = analyzer.run(discovery)
    status_finding = next(item for item in result.findings if item.id == "http-metadata:status")
    assert "404" in status_finding.description


def test_analyzer_execution_isolated_on_failure() -> None:
    """Analyzer base class should isolate execution failures."""

    class BrokenAnalyzer(HttpHeaderAnalyzer):
        def analyze_http(self, observation):  # type: ignore[no-untyped-def]
            raise RuntimeError("boom")

    analyzer = BrokenAnalyzer()
    result = analyzer.run(sample_discovery_with_http())
    assert result.findings == []
    assert result.errors
