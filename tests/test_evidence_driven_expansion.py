"""Phase 4 regression tests: evidence-driven detection expansion."""

from __future__ import annotations

from datetime import UTC, datetime

from techspecter.fingerprinting.analyzers.css_extract import extract_css_findings
from techspecter.fingerprinting.detection.candidates import (
    CandidateDetectionPipeline,
    CandidateStatus,
    IdentityKind,
)
from techspecter.fingerprinting.detection.candidates.mappings import (
    is_generic_css_selector,
    is_generic_html_element,
    resolve_bundle_identity,
    resolve_css_identity,
    resolve_html_identity,
    resolve_http_identity,
    resolve_runtime_identity,
)
from techspecter.fingerprinting.evidence.models import (
    Evidence,
    EvidenceCollection,
    EvidenceSource,
    EvidenceType,
    summarize_evidence,
)
from techspecter.fingerprinting.models import DetectionResult, PatternEvidence, Technology, TechnologyMatch
from techspecter.fingerprinting.pipeline.detection_pipeline import FingerprintPipeline
from techspecter.fingerprinting.pipeline.result_merger import merge_detection_results
from techspecter.models.discovery import DiscoveryResult, DownloadResult, Target
from techspecter.providers.merger import ProviderMerger
from techspecter.providers.models import ProviderDetectionResult, ProviderMatch
from techspecter.versioning.ownership import evidence_owned_by_technology


def _evidence(
    *,
    evidence_type: EvidenceType,
    matched_value: str,
    file: str = "bundle.js",
    url: str = "https://example.com/static/bundle.js",
    source: EvidenceSource = EvidenceSource.JAVASCRIPT,
    matched_pattern: str | None = None,
    metadata: dict[str, object] | None = None,
    confidence_hint: float = 0.0,
) -> Evidence:
    return Evidence(
        source=source,
        evidence_type=evidence_type,
        collector="test",
        file=file,
        url=url,
        matched_value=matched_value,
        matched_pattern=matched_pattern,
        metadata=metadata or {},
        confidence_hint=confidence_hint,
        timestamp=datetime.now(UTC),
    )


def _collection(*items: Evidence) -> EvidenceCollection:
    listed = list(items)
    return EvidenceCollection(
        target_url="https://example.com/",
        items=tuple(listed),
        summary=summarize_evidence(listed),
    )


def test_known_runtime_detection() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.RUNTIME_PATTERN,
            matched_value="ReactDOM.createRoot",
            metadata={"runtime_family": "react"},
        ),
    )
    result = CandidateDetectionPipeline().detect(collection)
    assert "react" in {item.technology.id for item in result.matches}


def test_unknown_structured_runtime_identity() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.RUNTIME_PATTERN,
            matched_value="__ACME_RUNTIME__",
            metadata={"runtime_family": "acme-runtime"},
        ),
    )
    candidates = CandidateDetectionPipeline().generate_candidates(collection)
    assert any(item.technology_id == "runtime:acme-runtime" for item in candidates)
    candidate = next(item for item in candidates if item.technology_id == "runtime:acme-runtime")
    assert candidate.knowledge_matched is False
    assert candidate.identity_kind == IdentityKind.RUNTIME
    assert candidate.source_file == "bundle.js"


def test_generic_runtime_word_rejection() -> None:
    assert resolve_runtime_identity("runtime", matched_value="runtime") is None
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.RUNTIME_PATTERN,
            matched_value="runtime",
            metadata={"runtime_family": "runtime"},
        ),
    )
    assert CandidateDetectionPipeline().generate_candidates(collection) == []


def test_known_bundler_detection() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.BUNDLE_RUNTIME,
            matched_value="__webpack_require__",
            metadata={"bundler": "webpack"},
        ),
    )
    result = CandidateDetectionPipeline().detect(collection)
    assert "webpack" in {item.technology.id for item in result.matches}


def test_structured_bundler_evidence_rollup() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.BUNDLE_RUNTIME,
            matched_value="rollupVersion",
            metadata={"bundler": "rollup"},
        ),
    )
    result = CandidateDetectionPipeline().detect(collection)
    assert "rollup" in {item.technology.id for item in result.matches}


def test_filename_only_bundler_rejection() -> None:
    assert resolve_bundle_identity(marker="app.chunk.js") is None
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.BUNDLE_MARKER,
            matched_value="app.chunk.js",
            file="app.chunk.js",
        ),
        _evidence(
            evidence_type=EvidenceType.FILENAME,
            matched_value="runtime.js",
            file="runtime.js",
        ),
    )
    candidates = CandidateDetectionPipeline().generate_candidates(collection)
    assert candidates == []


def test_known_css_framework_detection() -> None:
    findings = extract_css_findings("/*! Bootstrap v5.3.2 */\n.btn{display:block}")
    assert any(item.metadata.get("css_family") == "bootstrap" for item in findings)
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.CSS_MARKER,
            matched_value="/*! Bootstrap v5.3.2",
            file="bootstrap.min.css",
            url="https://example.com/bootstrap.min.css",
            source=EvidenceSource.CSS,
            metadata={"css_family": "bootstrap", "kind": "banner", "version": "5.3.2"},
            confidence_hint=90.0,
        ),
    )
    result = CandidateDetectionPipeline().detect(collection)
    match = next(item for item in result.matches if item.technology.id == "bootstrap")
    assert match.source_file == "bootstrap.min.css"
    assert match.version == "5.3.2"


def test_generic_css_selector_rejection() -> None:
    assert is_generic_css_selector(".btn")
    assert is_generic_css_selector("container")
    assert resolve_css_identity("btn", matched_value=".btn") is None
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.STRING_LITERAL,
            matched_value="bootstrap",
        ),
        _evidence(
            evidence_type=EvidenceType.CSS_MARKER,
            matched_value=".container",
            source=EvidenceSource.CSS,
            metadata={"css_family": "container", "kind": "selector"},
        ),
    )
    assert CandidateDetectionPipeline().detect(collection).matches == []


def test_css_and_js_same_technology_merge() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="bootstrap",
            file="app.js",
        ),
        _evidence(
            evidence_type=EvidenceType.CSS_MARKER,
            matched_value="bootstrap.min.css",
            file="bootstrap.min.css",
            source=EvidenceSource.CSS,
            metadata={"css_family": "bootstrap", "kind": "asset"},
            confidence_hint=85.0,
        ),
    )
    result = CandidateDetectionPipeline().detect(collection)
    bootstrap = [item for item in result.matches if item.technology.id == "bootstrap"]
    assert len(bootstrap) == 1
    assert len(bootstrap[0].evidence) >= 2


def test_known_html_framework_marker() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.HTML_MARKER,
            matched_value="__NEXT_DATA__",
            file="https://example.com/",
            url="https://example.com/",
            source=EvidenceSource.HTML,
            metadata={"kind": "ssr_marker", "html_family": "next.js"},
            confidence_hint=90.0,
        ),
    )
    result = CandidateDetectionPipeline().detect(collection)
    assert "nextjs" in {item.technology.id for item in result.matches}
    match = next(item for item in result.matches if item.technology.id == "nextjs")
    assert match.source_url == "https://example.com/"


def test_generic_html_element_rejection() -> None:
    assert is_generic_html_element("div")
    assert resolve_html_identity("div") is None
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.HTML_ELEMENT,
            matched_value="div",
            source=EvidenceSource.HTML,
        ),
        _evidence(
            evidence_type=EvidenceType.HTML_MARKER,
            matched_value="section",
            source=EvidenceSource.HTML,
            metadata={"kind": "element", "html_family": "section"},
        ),
    )
    assert CandidateDetectionPipeline().generate_candidates(collection) == []


def test_known_framework_header() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.HTTP_HEADER,
            matched_value="Express",
            matched_pattern="x-powered-by",
            source=EvidenceSource.NETWORK,
            metadata={"header": "x-powered-by"},
        ),
    )
    result = CandidateDetectionPipeline().detect(collection)
    assert "express" in {item.technology.id for item in result.matches}


def test_generic_header_value_rejection() -> None:
    assert resolve_http_identity("server", "unknown") is None
    assert resolve_http_identity("x-custom-header", "Something") is None
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.HTTP_HEADER,
            matched_value="unknown",
            matched_pattern="server",
            source=EvidenceSource.NETWORK,
            metadata={"header": "server"},
        ),
    )
    assert CandidateDetectionPipeline().generate_candidates(collection) == []


def test_open_http_powered_by_identity() -> None:
    resolved = resolve_http_identity("x-powered-by", "SomeFramework")
    assert resolved is not None
    assert resolved[0] == "http:someframework"
    assert resolved[3] is False


def test_source_map_package_identity_and_version() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.SOURCE_MAP_METADATA,
            matched_value="webpack://project/node_modules/some-map-lib/index.js",
        ),
        _evidence(
            evidence_type=EvidenceType.VERSION_CANDIDATE,
            matched_value="2.1.0",
            metadata={"package": "some-map-lib", "origin": "source_map"},
        ),
    )
    result = CandidateDetectionPipeline().detect(collection)
    match = next(item for item in result.matches if item.technology.id == "package:some-map-lib")
    assert match.version == "2.1.0"


def test_js_runtime_html_multi_source_merge() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="react",
            file="app.js",
        ),
        _evidence(
            evidence_type=EvidenceType.RUNTIME_PATTERN,
            matched_value="ReactDOM.createRoot",
            file="app.js",
            metadata={"runtime_family": "react"},
        ),
        _evidence(
            evidence_type=EvidenceType.HTML_MARKER,
            matched_value="data-reactroot",
            file="https://example.com/",
            source=EvidenceSource.HTML,
            metadata={"kind": "framework_hint", "html_family": "react"},
            confidence_hint=80.0,
        ),
    )
    result = CandidateDetectionPipeline().detect(collection)
    react = [item for item in result.matches if item.technology.id == "react"]
    assert len(react) == 1
    assert len(react[0].evidence) >= 2


def test_multiple_technologies_remain_independent() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="react",
        ),
        _evidence(
            evidence_type=EvidenceType.RUNTIME_PATTERN,
            matched_value="__NEXT_DATA__",
            metadata={"runtime_family": "next"},
        ),
        _evidence(
            evidence_type=EvidenceType.BUNDLE_RUNTIME,
            matched_value="__turbopack_load__",
            metadata={"bundler": "turbopack"},
        ),
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="custom-analytics",
        ),
    )
    result = CandidateDetectionPipeline().detect(collection)
    ids = {item.technology.id for item in result.matches}
    assert "react" in ids
    assert "nextjs" in ids
    assert "turbopack" in ids
    assert "package:custom-analytics" in ids


def test_react_version_does_not_leak() -> None:
    react_version = _evidence(
        evidence_type=EvidenceType.VERSION_CANDIDATE,
        matched_value="19.0.0",
        metadata={"technology": "react", "package": "react"},
    )
    assert evidence_owned_by_technology("react", react_version)
    assert not evidence_owned_by_technology("nextjs", react_version)
    assert not evidence_owned_by_technology("package:custom-analytics", react_version)


def test_unknown_version_remains_unknown() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="some-new-library",
        ),
    )
    match = next(
        item
        for item in CandidateDetectionPipeline().detect(collection).matches
        if item.technology.id == "package:some-new-library"
    )
    assert match.version == "Unknown"


def test_generic_string_and_filename_rejection() -> None:
    collection = _collection(
        _evidence(evidence_type=EvidenceType.STRING_LITERAL, matched_value="webpack"),
        _evidence(evidence_type=EvidenceType.FILENAME, matched_value="chunk.js"),
        _evidence(evidence_type=EvidenceType.STRING_LITERAL, matched_value="tailwind"),
    )
    assert CandidateDetectionPipeline().generate_candidates(collection) == []
    assert CandidateDetectionPipeline().detect(collection).matches == []


def test_legacy_fingerprint_still_works() -> None:
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        downloads=[
            DownloadResult(
                url="https://example.com/app.js",
                filename="app.js",
                content='reconcilerVersion:"19.0.0"; React.createElement("div");',
                download_success=True,
                status_code=200,
                content_type="application/javascript",
                content_length=50,
                download_duration_ms=1.0,
            ),
        ],
        inline_scripts=[],
    )
    result = FingerprintPipeline().run(discovery)
    assert "react" in {item.technology.id for item in result.matches}


def test_provider_failure_does_not_erase_candidates() -> None:
    results = [
        ProviderDetectionResult(
            provider="techspecter",
            target_url="https://example.com",
            matches=[
                ProviderMatch(
                    provider="techspecter",
                    technology_id="bootstrap",
                    name="Bootstrap",
                    category="css-framework",
                    confidence=85.0,
                    detection_method="candidate-engine",
                ),
            ],
        ),
        ProviderDetectionResult(
            provider="wappalyzer",
            target_url="https://example.com",
            success=False,
            error="unavailable",
        ),
    ]
    merged = ProviderMerger().merge(results, target_url="https://example.com")
    assert len(merged.matches) == 1
    assert merged.matches[0].technology.id == "bootstrap"


def test_legacy_and_candidate_dedupe() -> None:
    legacy = DetectionResult(
        target_url="https://example.com",
        matches=[
            TechnologyMatch(
                technology=Technology(id="webpack", name="webpack", category="build-tool"),
                confidence=90.0,
                matched_patterns=["string:__webpack_require__"],
                filename="app.js",
                source_file="app.js",
                evidence=[
                    PatternEvidence(
                        matcher="string",
                        pattern="__webpack_require__",
                        weight=40.0,
                        source_file="app.js",
                    ),
                ],
            ),
        ],
    )
    open_path = CandidateDetectionPipeline().detect(
        _collection(
            _evidence(
                evidence_type=EvidenceType.BUNDLE_RUNTIME,
                matched_value="__webpack_require__",
                file="app.js",
                metadata={"bundler": "webpack"},
            ),
        ),
    )
    merged = merge_detection_results(legacy, open_path)
    webpack = [item for item in merged.matches if item.technology.id == "webpack"]
    assert len(webpack) == 1


def test_cloudflare_cdn_cgi_path_produces_candidate() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.CSS_MARKER,
            matched_value="/cdn-cgi/",
            file="static-pages-2.6.0.css",
            url="https://example.com/cdn-cgi/assets/css/static-pages-2.6.0.css",
            source=EvidenceSource.CSS,
            metadata={"css_family": "cloudflare", "kind": "cdn_path"},
            confidence_hint=85.0,
        ),
    )
    result = CandidateDetectionPipeline().detect(collection)
    assert "cloudflare" in {item.technology.id for item in result.matches}

    content = "@tailwind base;\n@tailwind components;\n@tailwind utilities;\n"
    findings = extract_css_findings(content)
    assert any(item.metadata.get("css_family") == "tailwindcss" for item in findings)
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.CSS_MARKER,
            matched_value="@tailwind utilities",
            file="app.css",
            source=EvidenceSource.CSS,
            metadata={"css_family": "tailwindcss", "kind": "directive"},
            confidence_hint=90.0,
        ),
    )
    result = CandidateDetectionPipeline().detect(collection)
    assert "tailwindcss" in {item.technology.id for item in result.matches}


def test_wordpress_generator_html_marker() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.HTML_MARKER,
            matched_value="WordPress 6.4.2",
            source=EvidenceSource.HTML,
            metadata={"kind": "generator", "html_family": "wordpress"},
            confidence_hint=85.0,
        ),
    )
    result = CandidateDetectionPipeline().detect(collection)
    assert "wordpress" in {item.technology.id for item in result.matches}


def test_open_runtime_candidate_status_before_confirm() -> None:
    candidates = CandidateDetectionPipeline().generate_candidates(
        _collection(
            _evidence(
                evidence_type=EvidenceType.RUNTIME_PATTERN,
                matched_value="__ACME_RUNTIME__",
                metadata={"runtime_family": "acme-runtime"},
            ),
        ),
    )
    assert candidates[0].status == CandidateStatus.CANDIDATE
