"""Tests for Phase 6 JavaScript version detection engine."""

from __future__ import annotations

import pytest

import techspecter.javascript.adapter  # noqa: F401 — rebuild DiscoveryResult forward refs
from techspecter.fingerprinting.models import (
    UNKNOWN_VERSION,
    DetectionResult,
    Technology,
    TechnologyMatch,
)
from techspecter.models.discovery import DownloadResult, Target
from techspecter.versioning.confidence import score_method
from techspecter.versioning.engine import JavaScriptResourceContent, VersionDetectionEngine
from techspecter.versioning.extractors.react import ReactVersionExtractor
from techspecter.versioning.models import VersionEvidenceType
from techspecter.versioning.registry import VersionExtractorRegistry
from techspecter.versioning.validator import (
    is_valid_version,
    normalize_version,
    validate_and_normalize,
)
from tests.http_fixtures import sample_discovery_with_http


def test_normalize_version_strips_prefix() -> None:
    """Verify version prefix normalization."""
    assert normalize_version("v19.1.0") == "19.1.0"
    assert normalize_version('"18.2.0"') == "18.2.0"


def test_validate_accepts_semver_variants() -> None:
    """Verify semver-like versions are accepted."""
    assert validate_and_normalize("19.1.0") == "19.1.0"
    assert validate_and_normalize("5.3") == "5.3"
    assert validate_and_normalize("5.3.6") == "5.3.6"
    assert validate_and_normalize("15.3.2-beta") == "15.3.2-beta"
    assert validate_and_normalize("1.0.0-rc.1") == "1.0.0-rc.1"
    assert validate_and_normalize("2.0.0-alpha") == "2.0.0-alpha"


def test_validate_rejects_invalid_versions() -> None:
    """Verify invalid versions are rejected."""
    assert validate_and_normalize("") is None
    assert validate_and_normalize("not-a-version") is None
    assert validate_and_normalize("1") is None
    assert is_valid_version("abc.def.ghi") is False


def test_confidence_levels_by_method() -> None:
    """Verify confidence scoring maps methods to levels."""
    high_conf, high_level = score_method(VersionEvidenceType.RUNTIME_CONSTANT)
    medium_conf, medium_level = score_method(VersionEvidenceType.BANNER)
    low_conf, low_level = score_method(VersionEvidenceType.GENERIC_LITERAL)

    assert high_conf >= 90.0
    assert high_level.value == "high"
    assert medium_level.value == "medium"
    assert low_level.value == "low"
    assert low_conf < high_conf


def test_react_extractor_runtime_constant() -> None:
    """Verify React runtime constant extraction."""
    content = 'React.version="19.1.0";function App(){}'
    extractor = ReactVersionExtractor()
    results = extractor.extract(content, url="https://example.com/app.js", filename="app.js")
    assert results
    assert results[0].version == "19.1.0"
    assert results[0].method == VersionEvidenceType.RUNTIME_CONSTANT


def test_react_extractor_package_path() -> None:
    """Verify React package identifier extraction."""
    content = "node_modules/react-dom@18.2.0/index.js"
    extractor = ReactVersionExtractor()
    results = extractor.extract(content, url="https://example.com/bundle.js", filename="bundle.js")
    assert any(item.version == "18.2.0" for item in results)


def test_react_extractor_minified_bundle() -> None:
    """Verify extraction from minified JavaScript."""
    content = "/*! React v19.1.0 */React.version='19.1.0'"
    extractor = ReactVersionExtractor()
    results = extractor.extract(content, url="https://example.com/min.js", filename="min.js")
    versions = {item.version for item in results}
    assert "19.1.0" in versions


def test_registry_supports_required_technologies() -> None:
    """Verify all required technology extractors are registered."""
    registry = VersionExtractorRegistry()
    required = {
        "react",
        "nextjs",
        "angular",
        "vue",
        "jquery",
        "bootstrap",
        "tailwindcss",
        "material-ui",
        "leaflet",
        "webpack",
        "vite",
        "turbopack",
    }
    assert required.issubset(registry.supported_technology_ids)


def test_engine_enriches_unknown_version() -> None:
    """Verify version engine replaces Unknown with detected version."""
    engine = VersionDetectionEngine()
    resources = [
        JavaScriptResourceContent(
            url="https://example.com/app.js",
            filename="app.js",
            content='React.version="19.1.0"',
        ),
    ]
    result = engine.detect_for_technology("react", resources)
    assert result is not None
    assert result.version == "19.1.0"
    assert result.confidence >= 90.0
    assert result.evidence


def test_engine_enrich_detection_result() -> None:
    """Verify enrich updates DetectionResult matches."""
    engine = VersionDetectionEngine()
    detection = DetectionResult(
        target_url="https://example.com",
        matches=[
            TechnologyMatch(
                technology=Technology(id="bootstrap", name="Bootstrap", category="css-framework"),
                version=UNKNOWN_VERSION,
                confidence=80.0,
            ),
        ],
    )
    discovery = sample_discovery_with_http(
        target=Target(url="https://example.com", original_url="https://example.com"),
        downloads=[
            DownloadResult(
                url="https://example.com/bootstrap.min.js",
                filename="bootstrap.min.js",
                download_success=True,
                content="/*! Bootstrap v5.3.6 */",
            ),
        ],
    )
    enriched = engine.enrich(detection, discovery)
    assert enriched.matches[0].version == "5.3.6"
    assert enriched.matches[0].version_source is not None
    assert enriched.matches[0].version_confidence is not None


def test_engine_preserves_high_confidence_existing_version() -> None:
    """Verify engine does not downgrade a known high-confidence version."""
    engine = VersionDetectionEngine()
    detection = DetectionResult(
        target_url="https://example.com",
        matches=[
            TechnologyMatch(
                technology=Technology(id="react", name="React", category="framework"),
                version="18.2.0",
                confidence=90.0,
                version_confidence=95.0,
            ),
        ],
    )
    discovery = sample_discovery_with_http(
        target=Target(url="https://example.com", original_url="https://example.com"),
        downloads=[
            DownloadResult(
                url="https://example.com/app.js",
                filename="app.js",
                download_success=True,
                content='React.version="19.1.0"',
            ),
        ],
    )
    enriched = engine.enrich(detection, discovery)
    assert enriched.matches[0].version == "18.2.0"


def test_multiple_extraction_methods_ranked() -> None:
    """Verify best candidate is selected when multiple methods match."""
    engine = VersionDetectionEngine()
    content = "/*! React v19.1.0 */\n" "react@17.0.2\n" 'React.version="19.1.0";'
    resources = [
        JavaScriptResourceContent(
            url="https://example.com/app.js",
            filename="app.js",
            content=content,
        ),
    ]
    result = engine.detect_for_technology("react", resources)
    assert result is not None
    assert result.version == "19.1.0"
    assert result.candidates_considered >= 2


@pytest.mark.parametrize(
    ("extractor_cls", "technology_id", "content", "expected_version"),
    [
        (
            "techspecter.versioning.extractors.nextjs:NextJsVersionExtractor",
            "nextjs",
            '"nextVersion":"15.3.2"',
            "15.3.2",
        ),
        (
            "techspecter.versioning.extractors.webpack:WebpackVersionExtractor",
            "webpack",
            "/*! webpack 5.101.0 */",
            "5.101.0",
        ),
        (
            "techspecter.versioning.extractors.leaflet:LeafletVersionExtractor",
            "leaflet",
            'Leaflet.version="1.9.4"',
            "1.9.4",
        ),
        (
            "techspecter.versioning.extractors.jquery:JQueryVersionExtractor",
            "jquery",
            'jQuery.fn.jquery="3.7.1"',
            "3.7.1",
        ),
        (
            "techspecter.versioning.extractors.vue:VueVersionExtractor",
            "vue",
            'Vue.version="3.5.13"',
            "3.5.13",
        ),
    ],
)
def test_technology_specific_extractors(
    extractor_cls: str,
    technology_id: str,
    content: str,
    expected_version: str,
) -> None:
    """Verify technology-specific extractors resolve known version strings."""
    import importlib

    module_name, class_name = extractor_cls.split(":")
    module = importlib.import_module(module_name)
    extractor = getattr(module, class_name)()
    results = extractor.extract(content, url="https://example.com/lib.js", filename="lib.js")
    assert any(item.version == expected_version for item in results), results
    engine = VersionDetectionEngine()
    resources = [
        JavaScriptResourceContent(
            url="https://example.com/lib.js",
            filename="lib.js",
            content=content,
        ),
    ]
    detected = engine.detect_for_technology(technology_id, resources)
    assert detected is not None
    assert detected.version == expected_version
