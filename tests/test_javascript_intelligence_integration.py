"""Integration tests for JavaScript intelligence collectors."""

from __future__ import annotations

from techspecter.fingerprinting.analyzers.javascript import JavaScriptAnalyzer
from techspecter.fingerprinting.pipeline.evidence_pipeline import EvidencePipeline
from techspecter.models.discovery import DiscoveryResult, DownloadResult, InlineScript, Target


def test_javascript_analyzer_full_pipeline_on_webpack_bundle() -> None:
    """JavaScript analyzer should analyze webpack bundles comprehensively."""
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        downloads=[
            DownloadResult(
                url="https://example.com/app.min.js",
                filename="app.min.js",
                download_success=True,
                content="/* webpack */ function __webpack_require__(m){return m;}",
            ),
        ],
    )
    result = JavaScriptAnalyzer(fetch_source_maps=False).collect(discovery)
    types = {item.evidence_type.value for item in result.items}
    assert "script_content" in types
    assert "bundle_runtime" in types or "bundle_marker" in types


def test_evidence_pipeline_deduplicates_overlapping_collectors() -> None:
    """Pipeline should dedupe identical evidence from overlapping collectors."""
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        downloads=[
            DownloadResult(
                url="https://example.com/app.min.js",
                filename="app.min.js",
                download_success=True,
                content="__webpack_require__(1);",
            ),
        ],
    )
    collection = EvidencePipeline().collect(discovery)
    keys = [
        (item.url, item.file, item.evidence_type.value, item.matched_value)
        for item in collection.items
    ]
    assert len(keys) == len(set(keys))


def test_inline_script_analysis() -> None:
    """Inline scripts must be analyzed like downloaded resources."""
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        inline_scripts=[InlineScript(index=0, content="Vue.createApp({});")],
    )
    result = JavaScriptAnalyzer(fetch_source_maps=False).collect(discovery)
    assert any(item.evidence_type.value == "runtime_pattern" for item in result.items)
