"""Tests for evidence-only fingerprint analyzers."""

from __future__ import annotations

from techspecter.fingerprinting.analyzers.bundle import BundleAnalyzer
from techspecter.fingerprinting.analyzers.html import HTMLAnalyzer
from techspecter.fingerprinting.analyzers.javascript import JavaScriptAnalyzer
from techspecter.fingerprinting.analyzers.network import NetworkAnalyzer
from techspecter.fingerprinting.analyzers.package import PackageAnalyzer
from techspecter.models.discovery import DiscoveryResult, DownloadResult, InlineScript, Target
from tests.http_fixtures import sample_discovery_with_http


def test_network_analyzer_collects_header_evidence() -> None:
    """Network analyzer should emit HTTP header evidence."""
    discovery = sample_discovery_with_http()
    result = NetworkAnalyzer().collect(discovery)
    assert result.collector == "network-analyzer"
    assert result.items
    assert all(item.technology is None for item in result.items)
    assert any(item.evidence_type.value == "http_header" for item in result.items)


def test_html_analyzer_collects_script_references() -> None:
    """HTML analyzer should emit external and inline script evidence."""
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        external_scripts=[],
        inline_scripts=[InlineScript(index=0, content="console.log('x');")],
    )
    result = HTMLAnalyzer().collect(discovery)
    assert len(result.items) == 1
    assert result.items[0].source.value == "html"


def test_javascript_analyzer_collects_download_evidence() -> None:
    """JavaScript analyzer should emit content evidence for downloads."""
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        downloads=[
            DownloadResult(
                url="https://example.com/app.js",
                filename="app.js",
                download_success=True,
                content="console.log('app');",
            ),
        ],
    )
    result = JavaScriptAnalyzer().collect(discovery)
    assert len(result.items) == 1
    assert result.items[0].evidence_type.value == "script_content"


def test_bundle_analyzer_detects_bundle_filenames_only() -> None:
    """Bundle analyzer should collect filename markers without technology IDs."""
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        downloads=[
            DownloadResult(
                url="https://example.com/app.min.js",
                filename="app.min.js",
                download_success=True,
                content="/* min */",
            ),
        ],
    )
    result = BundleAnalyzer().collect(discovery)
    assert len(result.items) == 1
    assert result.items[0].technology is None


def test_package_analyzer_collects_module_markers() -> None:
    """Package analyzer should collect module markers as raw evidence."""
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        inline_scripts=[InlineScript(index=0, content="import React from 'react';")],
    )
    result = PackageAnalyzer().collect(discovery)
    assert result.items
    assert all(item.technology is None for item in result.items)
