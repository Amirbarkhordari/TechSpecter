"""Tests for evidence-driven technology match quality gates."""

from __future__ import annotations

from techspecter.fingerprinting.context import MatchContext
from techspecter.fingerprinting.engine import FingerprintEngine
from techspecter.fingerprinting.loader import SignatureLoader
from techspecter.fingerprinting.match_quality import MatchQualityGate, is_weak_pattern
from techspecter.fingerprinting.models import (
    UNKNOWN_VERSION,
    PatternEvidence,
    Technology,
    TechnologyMatch,
)
from techspecter.fingerprinting.pipeline.detection_pipeline import FingerprintPipeline
from techspecter.models.discovery import DiscoveryResult, DownloadResult, Target


def _match(
    *,
    tech_id: str,
    name: str,
    filename: str,
    confidence: float,
    patterns: list[tuple[str, str, float]],
    version: str = UNKNOWN_VERSION,
) -> TechnologyMatch:
    evidence = [
        PatternEvidence(matcher=matcher, pattern=pattern, weight=weight)
        for matcher, pattern, weight in patterns
    ]
    return TechnologyMatch(
        technology=Technology(id=tech_id, name=name, category="framework"),
        version=version,
        confidence=confidence,
        filename=filename,
        source_url=f"https://example.com/{filename}",
        evidence=evidence,
        matched_patterns=[f"{item.matcher}:{item.pattern}" for item in evidence],
    )


def test_weak_pattern_flags_generic_signatures() -> None:
    """Generic signatures should be classified as weak evidence."""
    assert is_weak_pattern("global", "ng")
    assert is_weak_pattern("filename", "chunk")
    assert is_weak_pattern("string", "Bootstrap")
    assert not is_weak_pattern("string", "__webpack_require__")


def test_technology_not_displayed_without_evidence() -> None:
    """Matches without evidence or source must be rejected."""
    gate = MatchQualityGate()
    empty = TechnologyMatch(
        technology=Technology(id="react", name="React", category="framework"),
        confidence=90.0,
        filename=None,
        source_url=None,
        evidence=[],
        matched_patterns=[],
    )
    assert gate.is_confirmed(empty) is False


def test_technology_displayed_with_valid_bundle_signature() -> None:
    """Valid JS bundle signatures should produce confirmed detections."""
    engine = FingerprintEngine(SignatureLoader().load_all())
    context = MatchContext(
        content='React.version="19.0.0"; reconcilerVersion:"19.0.0";',
        filename="framework.js",
        url="https://example.com/framework.js",
    )
    matches = engine.detect(context)
    react = next((item for item in matches if item.technology.id == "react"), None)
    assert react is not None
    assert react.filename == "framework.js"
    assert react.evidence
    assert react.version == "19.0.0"


def test_generic_keywords_do_not_create_confirmed_detection() -> None:
    """Single weak keyword matches must not be confirmed."""
    gate = MatchQualityGate()
    angular_fp = _match(
        tech_id="angular",
        name="Angular",
        filename="668.js",
        confidence=55.0,
        patterns=[("global", "ng", 25.0)],
    )
    bootstrap_fp = _match(
        tech_id="bootstrap",
        name="Bootstrap",
        filename="gtag.js",
        confidence=55.0,
        patterns=[("string", "Bootstrap", 25.0)],
    )
    webpack_fp = _match(
        tech_id="webpack",
        name="webpack",
        filename="928.js",
        confidence=40.0,
        patterns=[("filename", "chunk", 15.0)],
    )
    assert gate.is_confirmed(angular_fp) is False
    assert gate.is_confirmed(bootstrap_fp) is False
    assert gate.is_confirmed(webpack_fp) is False


def test_unknown_source_files_are_rejected() -> None:
    """Technologies without a discovered asset source must be rejected."""
    gate = MatchQualityGate()
    unknown = _match(
        tech_id="react",
        name="React",
        filename="unknown",
        confidence=95.0,
        patterns=[("string", "react", 35.0)],
    )
    unknown.filename = "unknown"
    unknown.source_url = None
    assert gate.is_confirmed(unknown) is False


def test_version_extraction_still_confirms_detection() -> None:
    """Resolved versions with strong confidence should confirm a detection."""
    gate = MatchQualityGate()
    react = _match(
        tech_id="react",
        name="React",
        filename="framework.js",
        confidence=72.0,
        patterns=[("string", "react", 20.0)],
        version="19.0.0",
    )
    react.version_confidence = 95.0
    assert gate.is_confirmed(react) is True


def test_engine_rejects_only_chunk_filename_for_webpack() -> None:
    """Chunk filenames alone must not detect webpack."""
    engine = FingerprintEngine(SignatureLoader().load_all())
    context = MatchContext(
        content="console.log('hello');",
        filename="928-f8fcd93b9c496fa5.js",
        url="https://example.com/_next/static/chunks/928-f8fcd93b9c496fa5.js",
    )
    matches = engine.detect(context)
    assert all(item.technology.id != "webpack" for item in matches)


def test_engine_detects_webpack_with_runtime_marker() -> None:
    """Webpack runtime markers in bundle content should be detected."""
    engine = FingerprintEngine(SignatureLoader().load_all())
    context = MatchContext(
        content="function r(e){return __webpack_require__(e)}",
        filename="webpack-91bd.js",
        url="https://example.com/webpack-91bd.js",
    )
    matches = engine.detect(context)
    assert any(item.technology.id == "webpack" for item in matches)


def test_pipeline_stores_ignored_weak_matches() -> None:
    """Pipeline should separate confirmed and ignored matches."""
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        downloads=[
            DownloadResult(
                url="https://example.com/chunk.js",
                filename="chunk.js",
                content="var foo = { ng: true, Bootstrap: 'text' };",
                download_success=True,
                status_code=200,
                content_type="application/javascript",
                content_length=64,
                download_duration_ms=1.0,
            )
        ],
        inline_scripts=[],
    )
    pipeline = FingerprintPipeline()
    result = pipeline.run(discovery)
    confirmed_ids = {item.technology.id for item in result.matches}
    assert "angular" not in confirmed_ids
    assert "bootstrap" not in confirmed_ids
    assert result.ignored_matches or not confirmed_ids
