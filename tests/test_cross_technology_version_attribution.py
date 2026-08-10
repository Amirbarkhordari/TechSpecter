"""Regression tests for cross-technology version attribution."""

from __future__ import annotations

from techspecter.fingerprinting.compatibility import FingerprintCompatibilityLayer
from techspecter.fingerprinting.detection.version.candidates import VersionCandidateCollector
from techspecter.fingerprinting.evidence.models import Evidence, EvidenceSource, EvidenceType
from techspecter.fingerprinting.models import UNKNOWN_VERSION, Technology, TechnologyMatch
from techspecter.fingerprinting.pipeline.detection_pipeline import FingerprintPipeline
from techspecter.fingerprinting.signatures.loader import TechnologySignatureLoader
from techspecter.models.discovery import DiscoveryResult, DownloadResult, Target
from techspecter.technology_intelligence.engine import TechnologyIntelligenceEngine
from techspecter.versioning.engine import (
    JavaScriptResourceContent,
    VersionDetectionEngine,
    resources_for_match,
)
from techspecter.versioning.ownership import evidence_owned_by_technology, version_evidence_relevant


def _bundle_js() -> str:
    return (
        'reconcilerVersion:"19.3.0-canary-test";'
        'rendererPackageName:"react-dom";'
        "self.__turbopack_load__ = () => {}; // TURBOPACK"
        'window.next={version:"0.0.0",appDir:!0};'
    )


def _discovery_with_bundle() -> DiscoveryResult:
    content = _bundle_js()
    return DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        downloads=[
            DownloadResult(
                url="https://example.com/_next/static/chunks/bundle.js",
                filename="bundle.js",
                download_success=True,
                content=content,
                status_code=200,
                content_type="application/javascript",
                content_length=len(content),
                download_duration_ms=1.0,
            ),
        ],
    )


def test_react_version_candidate_owned_only_by_react() -> None:
    """React-specific version evidence must not be owned by other technologies."""
    evidence = Evidence(
        source=EvidenceSource.JAVASCRIPT,
        evidence_type=EvidenceType.VERSION_CANDIDATE,
        matched_value="19.3.0-canary-test",
        matched_pattern=r'reconcilerVersion\s*:\s*"([\d.]+)"',
        collector="javascript-analyzer",
        metadata={"origin": "runtime", "technology": "react"},
    )
    assert evidence_owned_by_technology("react", evidence)
    assert not evidence_owned_by_technology("turbopack", evidence)
    assert not evidence_owned_by_technology("nextjs", evidence)


def test_generic_version_candidate_requires_technology_metadata() -> None:
    """Untagged version candidates must not attach to arbitrary technologies."""
    evidence = Evidence(
        source=EvidenceSource.JAVASCRIPT,
        evidence_type=EvidenceType.VERSION_CANDIDATE,
        matched_value="19.3.0-canary-test",
        collector="javascript-analyzer",
        metadata={"origin": "content"},
        url="https://example.com/bundle.js",
    )
    assert not version_evidence_relevant("turbopack", evidence, matched_evidence_ids=frozenset())
    assert not version_evidence_relevant("react", evidence, matched_evidence_ids=frozenset())


def test_collector_does_not_share_versions_across_technologies() -> None:
    """Version candidates from one technology must not appear for another."""
    registry = TechnologySignatureLoader()
    signatures = {item.id: item for item in registry.load_all()}
    react_evidence = Evidence(
        source=EvidenceSource.JAVASCRIPT,
        evidence_type=EvidenceType.VERSION_CANDIDATE,
        matched_value="19.3.0-canary-test",
        collector="javascript-analyzer",
        metadata={"technology": "react"},
        url="https://example.com/bundle.js",
    )
    turbopack_evidence = Evidence(
        id="turbopack-marker",
        source=EvidenceSource.JAVASCRIPT,
        evidence_type=EvidenceType.RUNTIME_PATTERN,
        matched_value="TURBOPACK",
        collector="javascript-analyzer",
        metadata={"technology": "turbopack"},
        url="https://example.com/bundle.js",
    )
    collector = VersionCandidateCollector()
    react_candidates = collector.collect(
        signatures["react"],
        evidence_items=(react_evidence, turbopack_evidence),
        matched_evidence_ids=frozenset({react_evidence.id}),
    )
    turbopack_candidates = collector.collect(
        signatures["turbopack"],
        evidence_items=(react_evidence, turbopack_evidence),
        matched_evidence_ids=frozenset({turbopack_evidence.id}),
    )
    assert any(item.version == "19.3.0-canary-test" for item in react_candidates)
    assert not turbopack_candidates


def test_fingerprint_pipeline_attributes_versions_per_technology() -> None:
    """Bundled JS must attribute React version only to React."""
    result = FingerprintPipeline().run(_discovery_with_bundle())
    versions = {item.technology.id: item.version for item in result.matches}
    assert "react" in versions
    assert versions["react"] == "19.3.0-canary-test"
    if "turbopack" in versions:
        assert versions["turbopack"] == UNKNOWN_VERSION
    if "nextjs" in versions:
        assert versions["nextjs"] == UNKNOWN_VERSION


def test_version_engine_scopes_resources_to_match_provenance() -> None:
    """Version extraction must not scan unrelated JavaScript resources."""
    match = TechnologyMatch(
        technology=Technology(id="turbopack", name="Turbopack", category="build-tool"),
        confidence=90.0,
        filename="turbopack-runtime.js",
        source_url="https://example.com/turbopack-runtime.js",
        matched_resources=["https://example.com/turbopack-runtime.js"],
    )
    resources = [
        JavaScriptResourceContent(
            url="https://example.com/turbopack-runtime.js",
            filename="turbopack-runtime.js",
            content="self.__turbopack_load__ = () => {}; // TURBOPACK",
        ),
        JavaScriptResourceContent(
            url="https://example.com/react-chunk.js",
            filename="react-chunk.js",
            content='reconcilerVersion:"19.3.0-canary-test";',
        ),
    ]
    scoped = resources_for_match(match, resources)
    assert len(scoped) == 1
    assert scoped[0].filename == "turbopack-runtime.js"
    detected = VersionDetectionEngine().detect_for_technology("turbopack", scoped)
    assert detected is None


def test_technology_intelligence_preserves_unknown_turbopack_version() -> None:
    """Technology intelligence must not inherit React version for Turbopack."""
    discovery = _discovery_with_bundle()
    detection = FingerprintPipeline().run(discovery)
    intelligence = TechnologyIntelligenceEngine().build(discovery, detection)
    by_id = {entry.technology.id: entry for entry in intelligence.technologies}
    assert by_id["react"].version == "19.3.0-canary-test"
    if "turbopack" in by_id:
        assert by_id["turbopack"].version == UNKNOWN_VERSION


def test_evidence_detection_does_not_cross_attribute_versions() -> None:
    """Evidence-based detection must keep technology-specific versions isolated."""
    discovery = _discovery_with_bundle()
    layer = FingerprintCompatibilityLayer()
    collection = layer.collect_evidence(discovery)
    explainable = layer.detect_from_evidence(collection)
    versions = {item.technology.id: item.version for item in explainable.detection.matches}
    if "react" in versions:
        assert versions["react"] != UNKNOWN_VERSION
    if "turbopack" in versions:
        assert versions["turbopack"] == UNKNOWN_VERSION


def test_invalid_zero_version_still_rejected_for_any_technology() -> None:
    """Placeholder versions remain rejected without suppressing detection."""
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        downloads=[
            DownloadResult(
                url="https://example.com/app.js",
                filename="app.js",
                download_success=True,
                content='window.next={version:"0.0.0"}; self.__next_f=[];',
                status_code=200,
                content_type="application/javascript",
                content_length=64,
                download_duration_ms=1.0,
            ),
        ],
    )
    result = FingerprintPipeline().run(discovery)
    nextjs = next(item for item in result.matches if item.technology.id == "nextjs")
    assert nextjs.version == UNKNOWN_VERSION
