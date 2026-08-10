"""Phase 2 regression tests: evidence-driven technology candidates."""

from __future__ import annotations

from datetime import UTC, datetime

from techspecter.fingerprinting.compatibility import FingerprintCompatibilityLayer
from techspecter.fingerprinting.detection.candidates import (
    CandidateDetectionPipeline,
    CandidateGenerator,
    CandidateStatus,
    CandidateValidator,
    EvidenceIndexer,
    TechnologyCandidate,
)
from techspecter.fingerprinting.detection.candidates.models import DiscoveryBasis
from techspecter.fingerprinting.evidence.models import (
    Evidence,
    EvidenceCollection,
    EvidenceSource,
    EvidenceType,
    summarize_evidence,
)
from techspecter.fingerprinting.models import DetectionResult, Technology, TechnologyMatch
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


def test_strong_package_evidence_creates_candidate() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="react",
            metadata={"package": "react"},
        ),
    )
    candidates = CandidateDetectionPipeline().generate_candidates(collection)
    assert any(item.technology_id == "react" for item in candidates)
    react = next(item for item in candidates if item.technology_id == "react")
    assert react.status == CandidateStatus.CANDIDATE
    assert react.discovery_basis == DiscoveryBasis.PACKAGE
    assert react.evidence


def test_strong_package_evidence_can_confirm() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="react-dom",
        ),
        _evidence(
            evidence_type=EvidenceType.RUNTIME_PATTERN,
            matched_value="ReactDOM.createRoot",
            metadata={"runtime_family": "react"},
        ),
    )
    result = CandidateDetectionPipeline().detect(collection)
    assert "react" in {item.technology.id for item in result.matches}
    match = next(item for item in result.matches if item.technology.id == "react")
    assert match.evidence
    assert match.source_file == "bundle.js"
    assert "candidate-engine" in match.detection_methods


def test_strong_runtime_evidence_creates_and_confirms() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.RUNTIME_PATTERN,
            matched_value="__NEXT_DATA__",
            metadata={"runtime_family": "next"},
            confidence_hint=80.0,
        ),
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="next",
        ),
    )
    pipeline = CandidateDetectionPipeline()
    candidates = pipeline.generate_candidates(collection)
    assert any(item.technology_id == "nextjs" for item in candidates)
    result = pipeline.detect(collection)
    assert "nextjs" in {item.technology.id for item in result.matches}


def test_string_literal_alone_does_not_confirm() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.STRING_LITERAL,
            matched_value="React",
        ),
        _evidence(
            evidence_type=EvidenceType.STRING_LITERAL,
            matched_value="Vue",
        ),
        _evidence(
            evidence_type=EvidenceType.STRING_LITERAL,
            matched_value="Bootstrap",
        ),
    )
    pipeline = CandidateDetectionPipeline()
    assert pipeline.generate_candidates(collection) == []
    assert pipeline.detect(collection).matches == []


def test_generic_technology_name_alone_does_not_confirm() -> None:
    # Script content / filename style weak evidence must not confirm.
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.SCRIPT_CONTENT,
            matched_value="React",
        ),
        _evidence(
            evidence_type=EvidenceType.FILENAME,
            matched_value="chunk",
            file="chunk.js",
        ),
    )
    result = CandidateDetectionPipeline().detect(collection)
    assert result.matches == []


def test_multi_signal_increases_confidence() -> None:
    single = _collection(
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="vue",
        ),
    )
    multi = _collection(
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="vue",
        ),
        _evidence(
            evidence_type=EvidenceType.RUNTIME_PATTERN,
            matched_value="Vue.createApp",
            metadata={"runtime_family": "vue"},
        ),
        _evidence(
            evidence_type=EvidenceType.IMPORT_EXPORT,
            matched_value="vue",
            metadata={"kind": "import"},
        ),
    )
    generator = CandidateGenerator()
    indexer = EvidenceIndexer()
    single_c = generator.generate(indexer.index(single))
    multi_c = generator.generate(indexer.index(multi))
    assert single_c and multi_c
    assert multi_c[0].confidence >= single_c[0].confidence
    assert multi_c[0].discovery_basis == DiscoveryBasis.MULTI_SIGNAL


def test_single_weak_evidence_rejected() -> None:
    candidate = TechnologyCandidate(
        technology_id="react",
        name="React",
        category="framework",
        evidence=(
            _evidence(
                evidence_type=EvidenceType.STRING_LITERAL,
                matched_value="React",
            ),
        ),
        discovery_basis=DiscoveryBasis.PACKAGE,
        confidence=90.0,
        source_file="app.js",
    )
    confirmed, rejected = CandidateValidator().validate([candidate])
    assert confirmed == []
    assert rejected[0].status == CandidateStatus.REJECTED


def test_multiple_technologies_from_one_bundle_independent() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.RUNTIME_PATTERN,
            matched_value="ReactDOM.createRoot",
            metadata={"runtime_family": "react"},
        ),
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
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="next",
        ),
        _evidence(
            evidence_type=EvidenceType.BUNDLE_MARKER,
            matched_value="__turbopack_load__",
            source=EvidenceSource.BUNDLE,
        ),
    )
    result = CandidateDetectionPipeline().detect(collection)
    ids = {item.technology.id for item in result.matches}
    assert {"react", "nextjs", "turbopack"}.issubset(ids)
    by_id = {item.technology.id: item for item in result.matches}
    react_patterns = {e.pattern for e in by_id["react"].evidence}
    next_patterns = {e.pattern for e in by_id["nextjs"].evidence}
    turbo_patterns = {e.pattern for e in by_id["turbopack"].evidence}
    assert react_patterns.isdisjoint(next_patterns)
    assert react_patterns.isdisjoint(turbo_patterns)


def test_candidate_provenance_preserved() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="axios",
            file="vendor.js",
            url="https://example.com/vendor.js",
        ),
        _evidence(
            evidence_type=EvidenceType.IMPORT_EXPORT,
            matched_value="axios",
            file="vendor.js",
            url="https://example.com/vendor.js",
            metadata={"kind": "import"},
        ),
    )
    result = CandidateDetectionPipeline().detect(collection)
    assert result.matches
    match = result.matches[0]
    assert match.technology.id == "axios"
    assert match.source_file == "vendor.js"
    assert match.source_url == "https://example.com/vendor.js"
    assert match.evidence
    assert match.supporting_evidence_ids


def test_evidence_less_candidate_cannot_confirm() -> None:
    candidate = TechnologyCandidate(
        technology_id="react",
        name="React",
        category="framework",
        evidence=(),
        discovery_basis=DiscoveryBasis.PACKAGE,
        confidence=99.0,
    )
    confirmed, rejected = CandidateValidator().validate([candidate])
    assert confirmed == []
    assert rejected[0].rejection_reason == "evidence-less candidate"


def test_legacy_fingerprint_detection_still_works() -> None:
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


def test_legacy_and_candidate_paths_merge_without_duplicates() -> None:
    legacy = DetectionResult(
        target_url="https://example.com",
        matches=[
            TechnologyMatch(
                technology=Technology(id="react", name="React", category="framework"),
                confidence=90.0,
                matched_patterns=["string:React.createElement"],
                filename="app.js",
                source_file="app.js",
                evidence=[],
            ),
        ],
    )
    # Fix legacy match to have evidence for merge evidence filter
    from techspecter.fingerprinting.models import PatternEvidence

    legacy.matches[0] = legacy.matches[0].model_copy(
        update={
            "evidence": [
                PatternEvidence(
                    matcher="string",
                    pattern="React.createElement",
                    weight=40.0,
                    source_file="app.js",
                ),
            ],
        },
    )
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
    )
    candidate_result = CandidateDetectionPipeline().detect(collection)
    merged = merge_detection_results(legacy, candidate_result)
    react_matches = [item for item in merged.matches if item.technology.id == "react"]
    assert len(react_matches) == 1
    assert react_matches[0].evidence


def test_provider_failure_does_not_erase_techspecter() -> None:
    results = [
        ProviderDetectionResult(
            provider="techspecter",
            target_url="https://example.com",
            matches=[
                ProviderMatch(
                    provider="techspecter",
                    technology_id="react",
                    name="React",
                    category="framework",
                    confidence=85.0,
                    version="19.0.0",
                    detection_method="fingerprint",
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
    assert merged.matches[0].technology.id == "react"


def test_candidate_version_ownership_remains_scoped() -> None:
    react_version = _evidence(
        evidence_type=EvidenceType.VERSION_CANDIDATE,
        matched_value="19.3.0-canary-test",
        metadata={"technology": "react", "origin": "runtime"},
    )
    assert evidence_owned_by_technology("react", react_version)
    assert not evidence_owned_by_technology("turbopack", react_version)
    assert not evidence_owned_by_technology("nextjs", react_version)


def test_parity_known_technology_legacy_and_candidate() -> None:
    content = (
        'reconcilerVersion:"19.0.0"; React.createElement("div"); '
        "ReactDOM.createRoot(document.getElementById('root'));"
    )
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        downloads=[
            DownloadResult(
                url="https://example.com/app.js",
                filename="app.js",
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
    legacy = FingerprintPipeline().run(discovery)
    assert "react" in {item.technology.id for item in legacy.matches}

    layer = FingerprintCompatibilityLayer()
    evidence = layer.collect_evidence(discovery)
    # Ensure structured package/runtime style evidence exists for candidate path
    # by injecting known strong evidence derived from the same asset semantics.
    enriched = list(evidence.items) + [
        _evidence(
            evidence_type=EvidenceType.RUNTIME_PATTERN,
            matched_value="ReactDOM.createRoot",
            file="app.js",
            url="https://example.com/app.js",
            metadata={"runtime_family": "react"},
        ),
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="react",
            file="app.js",
            url="https://example.com/app.js",
        ),
    ]
    collection = EvidenceCollection(
        target_url=evidence.target_url,
        items=tuple(enriched),
        summary=summarize_evidence(enriched),
    )
    candidate = layer.detect_candidates(collection)
    assert "react" in {item.technology.id for item in candidate.matches}
    merged = merge_detection_results(legacy, candidate)
    assert "react" in {item.technology.id for item in merged.matches}


def test_indexer_skips_string_literals() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.STRING_LITERAL,
            matched_value="react",
        ),
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="lodash",
        ),
    )
    index = EvidenceIndexer().index(collection)
    assert EvidenceType.STRING_LITERAL.value not in index.by_type
    assert index.by_package
