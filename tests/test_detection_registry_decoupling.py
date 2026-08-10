"""Phase 1 regression tests: detection decoupled from technology registry."""

from __future__ import annotations

from techspecter.fingerprinting.compatibility import FingerprintCompatibilityLayer
from techspecter.fingerprinting.detection.knowledge import (
    DetectionBasis,
    build_evidence_driven_match,
    is_evidence_backed_match,
    reject_evidence_less_matches,
)
from techspecter.fingerprinting.loader import SignatureLoader
from techspecter.fingerprinting.match_attribution import is_valid_detection_candidate
from techspecter.fingerprinting.models import (
    DetectionResult,
    PatternEvidence,
    Technology,
    TechnologyMatch,
)
from techspecter.fingerprinting.pipeline.detection_pipeline import FingerprintPipeline
from techspecter.fingerprinting.pipeline.result_merger import merge_detection_results
from techspecter.fingerprinting.signatures.registry import SignatureRegistry
from techspecter.models.discovery import DiscoveryResult, DownloadResult, Target
from techspecter.providers.merger import ProviderMerger
from techspecter.providers.models import ProviderDetectionResult, ProviderMatch
from techspecter.versioning.validator import is_valid_version


def _run(content: str, filename: str = "bundle.js") -> DetectionResult:
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        downloads=[
            DownloadResult(
                url=f"https://example.com/static/{filename}",
                filename=filename,
                content=content,
                download_success=True,
                status_code=200,
                content_type="application/javascript",
                content_length=len(content),
                download_duration_ms=1.0,
            ),
        ],
        inline_scripts=[],
    )
    return FingerprintPipeline().run(discovery)


def _confirmed_ids(result: DetectionResult) -> set[str]:
    return {item.technology.id for item in result.matches}


# --- 1. Registry technology still detectable with evidence ---


def test_registry_technology_detected_with_evidence() -> None:
    """Technologies in the registry must still be detected when evidence matches."""
    result = _run('reconcilerVersion:"19.0.0"; React.createElement("div");')
    assert "react" in _confirmed_ids(result)
    react = next(m for m in result.matches if m.technology.id == "react")
    assert react.detection_basis == DetectionBasis.EVIDENCE
    assert react.evidence


# --- 2. Detection requires evidence, not registry membership ---


def test_registry_only_technology_not_reported() -> None:
    """Catalog membership alone must not produce confirmed detections."""
    loader = SignatureLoader()
    all_fingerprints = loader.load_all()
    assert len(all_fingerprints) > 0

    empty = _run("")
    assert _confirmed_ids(empty) == set()

    registry_only = TechnologyMatch(
        technology=Technology(id="react", name="React", category="framework"),
        confidence=85.0,
        matched_patterns=[],
        evidence=[],
    )
    accepted, rejected = reject_evidence_less_matches([registry_only])
    assert accepted == []
    assert len(rejected) == 1


def test_merge_rejects_evidence_less_candidates() -> None:
    """Unified merge must discard matches lacking evidence, not unknown IDs."""
    evidence_match = TechnologyMatch(
        technology=Technology(id="react", name="React", category="framework"),
        confidence=85.0,
        matched_patterns=["string:React.createElement"],
        filename="app.js",
        source_file="app.js",
        evidence=[
            PatternEvidence(
                matcher="string",
                pattern="React.createElement",
                weight=40.0,
                source_file="app.js",
                matched_value="React.createElement",
            ),
        ],
        detection_basis=DetectionBasis.EVIDENCE,
    )
    registry_only = TechnologyMatch(
        technology=Technology(id="vue", name="Vue", category="framework"),
        confidence=90.0,
    )
    merged = merge_detection_results(
        DetectionResult(target_url="https://example.com", matches=[evidence_match, registry_only]),
        apply_quality_gate=False,
    )
    assert {m.technology.id for m in merged.matches} == {"react"}
    assert any(m.technology.id == "vue" for m in merged.ignored_matches)


# --- 3. No default technology output ---


def test_no_default_technology_output_on_empty_target() -> None:
    """Empty or generic content must not emit a default technology list."""
    generic = _run('"Bootstrap" mentioned in comment; var ng = 1; chunk loaded;')
    assert _confirmed_ids(generic) == set()


# --- 4. Multiple technologies from same JS asset ---


SYNTHETIC_BUNDLE = """
/* shared production bundle */
reconcilerVersion:"19.3.0-canary-f93b9fd4-20251217";
React.createElement("div");
window.next={version:"16.2.10",appDir:true};
__turbopack_load__(function(){});
turbopack-runtime
"""


def test_synthetic_bundle_multiple_independent_technologies() -> None:
    """One JS bundle may yield independent matches with separate evidence."""
    result = _run(SYNTHETIC_BUNDLE, filename="bundle.js")
    detected = _confirmed_ids(result)
    assert {"react", "nextjs", "turbopack"}.issubset(detected)

    by_id = {m.technology.id: m for m in result.matches}
    react = by_id["react"]
    nextjs = by_id["nextjs"]
    turbopack = by_id["turbopack"]

    assert react.source_file == "bundle.js"
    assert nextjs.source_file == "bundle.js"
    assert turbopack.source_file == "bundle.js"

    react_patterns = {e.pattern for e in react.evidence}
    next_patterns = {e.pattern for e in nextjs.evidence}
    turbopack_patterns = {e.pattern for e in turbopack.evidence}
    assert react_patterns.isdisjoint(next_patterns)
    assert react_patterns.isdisjoint(turbopack_patterns)
    assert next_patterns.isdisjoint(turbopack_patterns)

    assert react.version != nextjs.version or nextjs.version == "Unknown"
    assert turbopack.version == "Unknown"


# --- 5. Provenance survives detection ---


def test_technology_provenance_survives_detection() -> None:
    """Detected technologies must retain source, evidence, and matcher provenance."""
    result = _run('reconcilerVersion:"19.0.0"; React.createElement("div");', "framework.js")
    react = next(m for m in result.matches if m.technology.id == "react")
    assert react.source_file == "framework.js"
    assert react.evidence
    assert react.primary_matcher
    assert react.primary_pattern
    assert react.matched_value
    assert react.detection_reason


# --- 6. Provider merge preserves TechSpecter evidence detection ---


def test_provider_failure_does_not_erase_techspecter_results() -> None:
    """External provider failure must not remove valid TechSpecter detections."""
    techspecter_match = ProviderMatch(
        provider="techspecter",
        technology_id="react",
        name="React",
        category="framework",
        confidence=85.0,
        version="19.0.0",
        evidence_items=[],
        detection_method="fingerprint",
    )
    results = [
        ProviderDetectionResult(
            provider="techspecter",
            target_url="https://example.com",
            matches=[techspecter_match],
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
    assert merged.matches[0].technology.id == "react"


def test_evidence_detection_survives_provider_merge() -> None:
    """Evidence-based detection merged with provider output must not be dropped."""
    provider_result = DetectionResult(
        target_url="https://example.com",
        matches=[
            TechnologyMatch(
                technology=Technology(id="react", name="React", category="framework"),
                confidence=85.0,
                matched_patterns=["string:React.createElement"],
                filename="app.js",
                source_file="app.js",
                evidence=[
                    PatternEvidence(
                        matcher="string",
                        pattern="React.createElement",
                        weight=40.0,
                        source_file="app.js",
                    ),
                ],
                detection_basis=DetectionBasis.EVIDENCE,
                providers=["techspecter"],
            ),
        ],
    )
    evidence_result = DetectionResult(
        target_url="https://example.com",
        matches=[
            TechnologyMatch(
                technology=Technology(id="nextjs", name="Next.js", category="meta-framework"),
                confidence=80.0,
                matched_patterns=["string:__NEXT_DATA__"],
                filename="app.js",
                source_file="app.js",
                evidence=[
                    PatternEvidence(
                        matcher="string",
                        pattern="__NEXT_DATA__",
                        weight=45.0,
                        source_file="app.js",
                    ),
                ],
                detection_basis=DetectionBasis.EVIDENCE,
                detection_methods=["evidence-engine"],
            ),
        ],
    )
    merged = merge_detection_results(provider_result, evidence_result)
    assert {m.technology.id for m in merged.matches} == {"react", "nextjs"}


# --- 7. Version attribution remains technology-scoped ---


def test_version_attribution_technology_scoped_in_shared_bundle() -> None:
    """React version must not leak to Turbopack/Next.js in the same bundle."""
    result = _run(SYNTHETIC_BUNDLE, filename="bundle.js")
    by_id = {m.technology.id: m for m in result.matches}
    react = by_id.get("react")
    assert react is not None
    assert "19.3.0" in react.version
    for tech_id in ("nextjs", "turbopack"):
        other = by_id.get(tech_id)
        if other is None:
            continue
        if other.version != "Unknown":
            assert other.version != react.version


# --- 8. Invalid versions rejected ---


def test_invalid_placeholder_versions_rejected() -> None:
    """Placeholder versions like 0.0.0 must not be attributed."""
    assert not is_valid_version("0.0.0")
    assert not is_valid_version("0.0")
    assert is_valid_version("19.3.0-canary-f93b9fd4-20251217")


# --- 9. Negative generic keyword tests ---


def test_generic_keywords_do_not_confirm_technologies() -> None:
    """Generic strings alone must not create confirmed technology detections."""
    cases = [
        ('"Bootstrap"', {"bootstrap"}),
        ("ng", {"angular", "angularjs"}),
        ("chunk", set()),
        ('"React"', {"react"}),
        ('"Vue"', {"vue"}),
        ('"webpack"', {"webpack"}),
    ]
    for content, forbidden in cases:
        result = _run(content, filename="generic.js")
        confirmed = _confirmed_ids(result)
        overlap = confirmed & forbidden
        assert not overlap, (
            f"Generic content {content!r} must not confirm {overlap}, got {confirmed}"
        )


def test_generic_bootstrap_string_alone_not_confirmed() -> None:
    result = _run("/* uses bootstrap theme */", "styles.js")
    assert "bootstrap" not in _confirmed_ids(result)


def test_generic_ng_alone_not_confirmed() -> None:
    result = _run("var ng = window.ng || {};", "misc.js")
    assert "angular" not in _confirmed_ids(result)
    assert "angularjs" not in _confirmed_ids(result)


# --- 10. Evidence-driven match without registry lookup ---


def test_build_evidence_driven_match_without_registry() -> None:
    """Architecture must represent technologies proven by evidence outside the catalog."""
    match = build_evidence_driven_match(
        technology_id="custom-runtime",
        name="Custom Runtime",
        category="framework",
        confidence=75.0,
        source_file="runtime.js",
        evidence=[
            PatternEvidence(
                matcher="string",
                pattern="__CUSTOM_RUNTIME__",
                weight=50.0,
                source_file="runtime.js",
                matched_value="__CUSTOM_RUNTIME__",
            ),
        ],
    )
    assert is_evidence_backed_match(match)
    assert match.detection_basis == DetectionBasis.EVIDENCE
    assert match.technology.id == "custom-runtime"

    accepted, rejected = reject_evidence_less_matches([match])
    assert rejected == []
    assert accepted[0].technology.id == "custom-runtime"

    merged = merge_detection_results(
        DetectionResult(target_url="https://example.com", matches=[match]),
        apply_quality_gate=False,
    )
    assert {m.technology.id for m in merged.matches} == {"custom-runtime"}


# --- 11. Signature registry is knowledge source ---


def test_signature_registry_provides_knowledge_not_whitelist() -> None:
    """Registry resolves signatures for evaluation; empty evidence yields no detections."""
    registry = SignatureRegistry()
    signatures = registry.resolve()
    assert len(signatures) > 0

    layer = FingerprintCompatibilityLayer()
    empty_discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        downloads=[],
        inline_scripts=[],
    )
    evidence = layer.collect_evidence(empty_discovery)
    explainable = layer.detect_from_evidence(evidence)
    assert explainable.detection.matches == []


# --- 12. Evidence-based detection is evidence-backed ---


def test_evidence_engine_matches_are_evidence_backed() -> None:
    """Evidence detection pipeline must tag matches as evidence-driven."""
    content = 'window.next={version:"16.2.10"}; __NEXT_DATA__ = {};'
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        downloads=[
            DownloadResult(
                url="https://example.com/_next/static/chunks/main.js",
                filename="main.js",
                content=content,
                download_success=True,
                status_code=200,
                content_type="application/javascript",
                content_length=len(content),
                download_duration_ms=1.0,
            ),
        ],
        inline_scripts=[],
    )
    layer = FingerprintCompatibilityLayer()
    evidence = layer.collect_evidence(discovery)
    explainable = layer.detect_from_evidence(evidence)
    for match in explainable.detection.matches:
        assert is_valid_detection_candidate(match)
        assert match.detection_basis == DetectionBasis.EVIDENCE
