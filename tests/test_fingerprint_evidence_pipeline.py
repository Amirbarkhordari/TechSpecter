"""Tests for the evidence collection pipeline."""

from __future__ import annotations

from techspecter.fingerprinting.compatibility import FingerprintCompatibilityLayer
from techspecter.fingerprinting.pipeline import EvidencePipeline, FingerprintPipeline
from techspecter.fingerprints.pipeline import FingerprintPipeline as LegacyShimPipeline
from techspecter.models.discovery import DiscoveryResult, DownloadResult, InlineScript, Target
from tests.http_fixtures import sample_discovery_with_http


def test_evidence_pipeline_collects_without_detection() -> None:
    """Evidence pipeline should aggregate evidence without technology matches."""
    discovery = sample_discovery_with_http(
        downloads=[
            DownloadResult(
                url="https://example.com/app.min.js",
                filename="app.min.js",
                download_success=True,
                content="import x from 'y';",
            ),
        ],
        inline_scripts=[InlineScript(index=0, content="console.log('inline');")],
    )
    collection = EvidencePipeline().collect(discovery)
    assert collection.target_url == "https://example.com/"
    assert collection.summary.total_items > 0
    assert all(item.technology is None for item in collection.items)
    assert "network-analyzer" in collection.summary.collectors


def test_legacy_detection_pipeline_still_detects_technologies() -> None:
    """Legacy fingerprint pipeline must remain backward compatible."""
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        downloads=[
            DownloadResult(
                url="https://example.com/react.js",
                filename="react.js",
                download_success=True,
                content='React.version="18.2.0"; React.createElement("div");',
            ),
        ],
    )
    result = FingerprintPipeline().run(discovery)
    assert any(match.technology.id == "react" for match in result.matches)


def test_fingerprints_shim_exports_detection_pipeline() -> None:
    """Backward-compatible fingerprints.pipeline shim should still work."""
    assert LegacyShimPipeline is FingerprintPipeline


def test_compatibility_layer_runs_both_pipelines() -> None:
    """Compatibility layer should return detection and evidence together."""
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        downloads=[
            DownloadResult(
                url="https://example.com/react.js",
                filename="react.js",
                download_success=True,
                content='ReactDOM.createRoot(document.getElementById("root")); React.version="18.2.0";',
            ),
        ],
    )
    detection, evidence = FingerprintCompatibilityLayer().analyze(discovery)
    assert detection.matches
    assert evidence.summary.total_items >= 0
