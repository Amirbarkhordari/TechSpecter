"""Phase 3 regression tests: open-world package identity discovery."""

from __future__ import annotations

from datetime import UTC, datetime

from techspecter.fingerprinting.detection.candidates import (
    CandidateDetectionPipeline,
    CandidateStatus,
    CandidateValidator,
    EvidenceIndexer,
    IdentityKind,
)
from techspecter.fingerprinting.detection.candidates.mappings import (
    is_relative_module,
    normalize_package_key,
    resolve_package_identity,
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


def test_unknown_package_reference_produces_candidate() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="some-new-library",
        ),
    )
    candidates = CandidateDetectionPipeline().generate_candidates(collection)
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.technology_id == "package:some-new-library"
    assert candidate.knowledge_matched is False
    assert candidate.identity_kind == IdentityKind.PACKAGE
    assert candidate.status == CandidateStatus.CANDIDATE


def test_known_package_still_resolves_to_catalog() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="react",
        ),
    )
    candidates = CandidateDetectionPipeline().generate_candidates(collection)
    assert candidates[0].technology_id == "react"
    assert candidates[0].name == "React"
    assert candidates[0].knowledge_matched is True


def test_scoped_package_normalization() -> None:
    assert normalize_package_key("@scope/package/submodule") == "@scope/package"
    identity = resolve_package_identity("@scope/package/utils")
    assert identity is not None
    assert identity[0] == "package:@scope/package"
    assert identity[3] is False


def test_package_subpath_normalizes_to_root() -> None:
    assert normalize_package_key("lodash/map") == "lodash"
    identity = resolve_package_identity("lodash/fp")
    assert identity is not None
    assert identity[0] == "lodash"  # known catalog
    assert identity[3] is True


def test_relative_import_does_not_create_candidate() -> None:
    assert is_relative_module("./utils")
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="./utils",
            metadata={"kind": "import"},
        ),
        _evidence(
            evidence_type=EvidenceType.IMPORT_EXPORT,
            matched_value="../lib/core",
            metadata={"kind": "import"},
        ),
    )
    candidates = CandidateDetectionPipeline().generate_candidates(collection)
    assert candidates == []
    assert CandidateDetectionPipeline().detect(collection).matches == []


def test_generic_string_literal_does_not_create_package_identity() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.STRING_LITERAL,
            matched_value="some-new-library",
        ),
    )
    assert CandidateDetectionPipeline().generate_candidates(collection) == []


def test_es_module_and_commonjs_package_import_produce_candidate() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="some-new-library",
            metadata={"kind": "import"},
        ),
        _evidence(
            evidence_type=EvidenceType.IMPORT_EXPORT,
            matched_value="another-lib",
            metadata={"kind": "import"},
        ),
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="another-lib",
            metadata={"kind": "require"},
        ),
    )
    candidates = CandidateDetectionPipeline().generate_candidates(collection)
    ids = {item.technology_id for item in candidates}
    assert "package:some-new-library" in ids
    assert "package:another-lib" in ids


def test_unknown_package_can_confirm_with_structured_evidence() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="some-new-library",
            file="vendor.js",
            url="https://example.com/vendor.js",
        ),
    )
    result = CandidateDetectionPipeline().detect(collection)
    assert "package:some-new-library" in {item.technology.id for item in result.matches}
    match = next(item for item in result.matches if item.technology.id == "package:some-new-library")
    assert match.source_file == "vendor.js"
    assert match.evidence
    assert match.version == "Unknown"


def test_multiple_unknown_packages_remain_independent() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="alpha-lib",
        ),
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="beta-lib",
        ),
    )
    result = CandidateDetectionPipeline().detect(collection)
    ids = {item.technology.id for item in result.matches}
    assert ids == {"package:alpha-lib", "package:beta-lib"}


def test_known_and_unknown_packages_coexist_in_bundle() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="react",
        ),
        _evidence(
            evidence_type=EvidenceType.RUNTIME_PATTERN,
            matched_value="ReactDOM.createRoot",
            metadata={"runtime_family": "react"},
        ),
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="custom-analytics",
        ),
    )
    result = CandidateDetectionPipeline().detect(collection)
    ids = {item.technology.id for item in result.matches}
    assert "react" in ids
    assert "package:custom-analytics" in ids


def test_package_owned_version_attaches_correctly() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="some-new-library",
            metadata={"version": "4.2.1", "package": "some-new-library"},
        ),
        _evidence(
            evidence_type=EvidenceType.VERSION_CANDIDATE,
            matched_value="4.2.1",
            metadata={"package": "some-new-library", "origin": "package_json_fragment"},
        ),
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="other-lib",
        ),
    )
    result = CandidateDetectionPipeline().detect(collection)
    by_id = {item.technology.id: item for item in result.matches}
    assert by_id["package:some-new-library"].version == "4.2.1"
    assert by_id["package:other-lib"].version == "Unknown"


def test_version_does_not_leak_across_packages() -> None:
    react_version = _evidence(
        evidence_type=EvidenceType.VERSION_CANDIDATE,
        matched_value="19.3.0",
        metadata={"technology": "react", "package": "react"},
    )
    assert evidence_owned_by_technology("react", react_version)
    assert not evidence_owned_by_technology("package:some-new-library", react_version)


def test_conservative_utility_package_not_auto_confirmed() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            matched_value="utils",
        ),
    )
    pipeline = CandidateDetectionPipeline()
    candidates = pipeline.generate_candidates(collection)
    assert any(item.technology_id == "package:utils" for item in candidates)
    assert pipeline.detect(collection).matches == []


def test_candidate_validation_uses_quality_gate() -> None:
    # Evidence-less candidate cannot confirm even with high confidence.
    from techspecter.fingerprinting.detection.candidates.models import (
        DiscoveryBasis,
        TechnologyCandidate,
    )

    candidate = TechnologyCandidate(
        technology_id="package:ghost",
        name="ghost",
        category="unknown",
        evidence=(),
        discovery_basis=DiscoveryBasis.PACKAGE,
        confidence=99.0,
        knowledge_matched=False,
        identity_kind=IdentityKind.PACKAGE,
    )
    confirmed, rejected = CandidateValidator().validate([candidate])
    assert confirmed == []
    assert rejected[0].rejection_reason == "evidence-less candidate"


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


def test_legacy_and_open_package_dedupe_known_tech() -> None:
    legacy = DetectionResult(
        target_url="https://example.com",
        matches=[
            TechnologyMatch(
                technology=Technology(id="react", name="React", category="framework"),
                confidence=90.0,
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
            ),
        ],
    )
    open_path = CandidateDetectionPipeline().detect(
        _collection(
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
        ),
    )
    merged = merge_detection_results(legacy, open_path)
    react = [item for item in merged.matches if item.technology.id == "react"]
    assert len(react) == 1


def test_provider_failure_does_not_erase_open_candidates() -> None:
    results = [
        ProviderDetectionResult(
            provider="techspecter",
            target_url="https://example.com",
            matches=[
                ProviderMatch(
                    provider="techspecter",
                    technology_id="package:some-new-library",
                    name="some-new-library",
                    category="unknown",
                    confidence=80.0,
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
    assert merged.matches[0].technology.id == "package:some-new-library"


def test_source_map_package_path_can_create_candidate() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.SOURCE_MAP_METADATA,
            matched_value="webpack://project/node_modules/some-map-lib/index.js",
            source=EvidenceSource.JAVASCRIPT,
        ),
    )
    candidates = CandidateDetectionPipeline().generate_candidates(collection)
    assert any(item.technology_id == "package:some-map-lib" for item in candidates)


def test_indexer_indexes_source_map_packages() -> None:
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.SOURCE_MAP_METADATA,
            matched_value="node_modules/@scope/pkg/dist/index.js",
        ),
    )
    index = EvidenceIndexer().index(collection)
    assert EvidenceType.SOURCE_MAP_METADATA.value in index.by_type
    assert index.by_package
