"""Regression tests for invalid technology version rejection."""

from __future__ import annotations

from techspecter.fingerprinting.context import MatchContext
from techspecter.fingerprinting.engine import FingerprintEngine
from techspecter.fingerprinting.extractor import VersionExtractor
from techspecter.fingerprinting.loader import SignatureLoader
from techspecter.fingerprinting.match_attribution import select_best_version_match
from techspecter.fingerprinting.models import (
    UNKNOWN_VERSION,
    DetectionResult,
    Technology,
    TechnologyMatch,
)
from techspecter.fingerprinting.pipeline.detection_pipeline import FingerprintPipeline
from techspecter.models.discovery import DiscoveryResult, DownloadResult, Target
from techspecter.versioning.engine import JavaScriptResourceContent, VersionDetectionEngine
from techspecter.versioning.extractors.nextjs import NextJsVersionExtractor
from techspecter.versioning.extractors.turbopack import TurbopackVersionExtractor
from techspecter.versioning.validator import (
    is_placeholder_version,
    is_valid_version,
    validate_and_normalize,
)


def test_placeholder_versions_are_rejected() -> None:
    """0.0.0 and related placeholders must not be valid versions."""
    assert is_placeholder_version("0.0.0") is True
    assert is_placeholder_version("0.0") is True
    assert is_placeholder_version("0") is True
    assert validate_and_normalize("0.0.0") is None
    assert validate_and_normalize("0.0") is None
    assert validate_and_normalize("0") is None


def test_valid_versions_remain_accepted() -> None:
    """Legitimate versions including prerelease/canary must remain valid."""
    assert validate_and_normalize("1.0.0") == "1.0.0"
    assert validate_and_normalize("2.4.1") == "2.4.1"
    assert validate_and_normalize("19.3.0") == "19.3.0"
    assert (
        validate_and_normalize("19.3.0-canary-f93b9fd4-20251217")
        == "19.3.0-canary-f93b9fd4-20251217"
    )
    assert validate_and_normalize("16.2.10") == "16.2.10"
    assert validate_and_normalize("4.17.23") == "4.17.23"
    assert validate_and_normalize("0.1.0") == "0.1.0"
    assert is_valid_version("1.0.0-rc.1") is True


def test_nextjs_extractor_rejects_zero_version() -> None:
    """Next.js runtime placeholder versions must be rejected."""
    content = 'window.next={version:"0.0.0",appDir:!0}'
    extractor = NextJsVersionExtractor()
    assert extractor.extract(content, url="https://example.com/app.js", filename="app.js") == []


def test_turbopack_extractor_rejects_zero_version_from_filename() -> None:
    """Filename-derived placeholder versions must not become Turbopack versions."""
    content = "self.__turbopack_load__ = () => {}; // TURBOPACK runtime"
    extractor = TurbopackVersionExtractor()
    results = extractor.extract(
        content,
        url="https://example.com/turbopack-c9b173b4.js",
        filename="turbopack-c9b173b4.js",
    )
    assert results == []


def test_fingerprint_version_extractor_rejects_zero_version() -> None:
    """Legacy fingerprint version extraction must reject placeholder versions."""
    loader = SignatureLoader()
    nextjs = next(item for item in loader.load_all() if item.id == "nextjs")
    version, pattern = VersionExtractor().extract_with_pattern(
        nextjs,
        MatchContext(
            content='window.next={version:"0.0.0",appDir:!0}',
            filename="bootstrap.js",
            url="https://example.com/bootstrap.js",
        ),
    )
    assert version == UNKNOWN_VERSION
    assert pattern is None


def test_technology_remains_when_only_invalid_version_exists() -> None:
    """Invalid versions must not suppress confirmed technology detection."""
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        downloads=[
            DownloadResult(
                url="https://example.com/_next/static/chunks/app.js",
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
    assert nextjs.confidence >= 50.0


def test_valid_candidate_wins_over_invalid_candidate() -> None:
    """When both invalid and valid candidates exist, the valid one must win."""
    engine = VersionDetectionEngine()
    content = (
        'window.next={version:"0.0.0",appDir:!0};'
        'window.next={version:"16.2.10",appDir:!0};'
    )
    resources = [
        JavaScriptResourceContent(
            url="https://example.com/bootstrap.js",
            filename="bootstrap.js",
            content=content,
        ),
    ]
    detected = engine.detect_for_technology("nextjs", resources)
    assert detected is not None
    assert detected.version == "16.2.10"


def test_engine_sanitizes_invalid_existing_version() -> None:
    """Pre-existing invalid versions on matches must become Unknown."""
    engine = VersionDetectionEngine()
    detection = DetectionResult(
        target_url="https://example.com",
        matches=[
            TechnologyMatch(
                technology=Technology(id="nextjs", name="Next.js", category="framework"),
                version="0.0.0",
                confidence=100.0,
                version_confidence=95.0,
            ),
        ],
    )
    discovery = DiscoveryResult(
        target=Target(url="https://example.com", original_url="https://example.com"),
        downloads=[],
    )
    enriched = engine.enrich(detection, discovery)
    assert enriched.matches[0].version == UNKNOWN_VERSION
    assert enriched.matches[0].confidence == 100.0


def test_turbopack_and_nextjs_remain_confirmed_without_valid_version() -> None:
    """Technologies stay confirmed when no reliable version exists."""
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        downloads=[
            DownloadResult(
                url="https://example.com/turbopack-runtime.js",
                filename="turbopack-runtime.js",
                download_success=True,
                content="self.__turbopack_load__ = () => {}; // TURBOPACK",
                status_code=200,
                content_type="application/javascript",
                content_length=64,
                download_duration_ms=1.0,
            ),
            DownloadResult(
                url="https://example.com/bootstrap.js",
                filename="bootstrap.js",
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
    confirmed = {item.technology.id: item.version for item in result.matches}
    assert confirmed["turbopack"] == UNKNOWN_VERSION
    assert confirmed["nextjs"] == UNKNOWN_VERSION


def test_react_canary_version_remains_valid() -> None:
    """React canary versions must continue to be accepted."""
    engine = VersionDetectionEngine()
    content = (
        'eE=f4.inject({bundleType:0,version:"19.3.0-canary-f93b9fd4-20251217",'
        'rendererPackageName:"react-dom",reconcilerVersion:"19.3.0-canary-f93b9fd4-20251217"})'
    )
    resources = [
        JavaScriptResourceContent(
            url="https://example.com/chunk.js",
            filename="chunk.js",
            content=content,
        ),
    ]
    detected = engine.detect_for_technology("react", resources)
    assert detected is not None
    assert detected.version == "19.3.0-canary-f93b9fd4-20251217"


def test_select_best_version_match_ignores_invalid_versions() -> None:
    """Version merge must ignore invalid placeholder versions."""
    invalid = TechnologyMatch(
        technology=Technology(id="nextjs", name="Next.js", category="framework"),
        version="0.0.0",
        confidence=100.0,
        version_confidence=95.0,
    )
    valid = TechnologyMatch(
        technology=Technology(id="nextjs", name="Next.js", category="framework"),
        version="16.2.10",
        confidence=90.0,
        version_confidence=80.0,
    )
    selected = select_best_version_match([invalid, valid])
    assert selected is not None
    assert selected.version == "16.2.10"


def test_fingerprint_engine_does_not_emit_zero_version() -> None:
    """FingerprintEngine must not attach 0.0.0 to technology matches."""
    loader = SignatureLoader()
    engine = FingerprintEngine(loader.load_all())
    context = MatchContext(
        content='window.next={version:"0.0.0"}; self.__next_f=[];',
        filename="page.js",
        url="https://example.com/page.js",
    )
    matches = engine.detect(context)
    nextjs = next(item for item in matches if item.technology.id == "nextjs")
    assert nextjs.version == UNKNOWN_VERSION
