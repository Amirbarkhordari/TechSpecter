"""Phase 4.5 detection quality tests."""

from __future__ import annotations

from datetime import UTC, datetime

from techspecter.fingerprinting.detection.merger import TechnologyMerger
from techspecter.fingerprinting.detection.models import VersionResolution
from techspecter.fingerprinting.detection.pipeline import EvidenceDetectionPipeline
from techspecter.fingerprinting.detection.scoring import ConfidenceEngine
from techspecter.fingerprinting.detection.version.candidates import (
    VersionCandidateCollector,
    normalize_version,
)
from techspecter.fingerprinting.detection.version_resolver import VersionResolutionEngine
from techspecter.fingerprinting.evidence.models import (
    Evidence,
    EvidenceCollection,
    EvidenceSource,
    EvidenceType,
)
from techspecter.fingerprinting.models import Technology, TechnologyMatch
from techspecter.fingerprinting.signatures.loader import TechnologySignatureLoader


def _evidence(
    *,
    evidence_type: EvidenceType,
    value: str,
    source: EvidenceSource = EvidenceSource.JAVASCRIPT,
    file: str = "app.js",
    url: str = "https://example.com/app.js",
    metadata: dict[str, object] | None = None,
) -> Evidence:
    """Build test evidence item."""
    return Evidence(
        source=source,
        evidence_type=evidence_type,
        collector="test",
        matched_value=value,
        file=file,
        url=url,
        metadata=metadata or {},
        timestamp=datetime.now(UTC),
    )


def _collection(*items: Evidence, target_url: str = "https://example.com/") -> EvidenceCollection:
    """Build evidence collection from items."""
    return EvidenceCollection(target_url=target_url, items=items)


def test_version_resolution_from_cross_file_candidates() -> None:
    """Version resolver should correlate candidates across resources."""
    loader = TechnologySignatureLoader()
    react = next(item for item in loader.load_all() if item.id == "react")
    evidence = (
        _evidence(
            evidence_type=EvidenceType.RUNTIME_PATTERN,
            value="ReactDOM.createRoot",
            file="main.js",
            url="https://example.com/main.js",
        ),
        _evidence(
            evidence_type=EvidenceType.VERSION_CANDIDATE,
            value="19.1.0",
            file="vendor.js",
            url="https://example.com/vendor.js",
            metadata={"technology": "react", "origin": "package"},
        ),
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            value="react@19.1.0",
            file="vendor.js",
            url="https://example.com/vendor.js",
        ),
    )
    from techspecter.fingerprinting.detection.normalizer import normalize_evidence
    from techspecter.fingerprinting.detection.rules import RuleEvaluator

    collection = _collection(*evidence)
    evaluation = RuleEvaluator().evaluate(react, normalize_evidence(collection))
    resolution = VersionResolutionEngine().resolve(
        react,
        evidence_items=collection.items,
        matched_rules=evaluation.matched_rules,
    )
    assert resolution.version == "19.1.0"
    assert resolution.confidence > 0
    assert resolution.candidate_count >= 1


def test_react_resolves_version_from_same_resource_candidate() -> None:
    """React should resolve version from VERSION_CANDIDATE on matched resource."""
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.RUNTIME_PATTERN,
            value="ReactDOM.createRoot",
            metadata={"runtime_family": "react"},
        ),
        _evidence(evidence_type=EvidenceType.PACKAGE_REFERENCE, value="react"),
        _evidence(evidence_type=EvidenceType.VERSION_CANDIDATE, value="19.1.0", metadata={"technology": "react"}),
    )
    result = EvidenceDetectionPipeline().detect(collection)
    match = next(item for item in result.detection.matches if item.technology.id == "react")
    assert match.version == "19.1.0"
    assert match.version_confidence is not None
    assert match.version_confidence > 0


def test_duplicate_suppression_merges_same_technology() -> None:
    """Merger should emit one detection per technology."""
    tech = Technology(id="react", name="React", category="frameworks")
    matches = [
        TechnologyMatch(
            technology=tech,
            version="19.1.0",
            confidence=80.0,
            matched_patterns=["a"],
            supporting_evidence_ids=["e1"],
            evidence_count=1,
            matched_resources=["a.js"],
            version_source="runtime",
        ),
        TechnologyMatch(
            technology=tech,
            version="19.1.0",
            confidence=75.0,
            matched_patterns=["b"],
            supporting_evidence_ids=["e2"],
            evidence_count=1,
            matched_resources=["b.js"],
            version_source="package",
        ),
    ]
    merged = TechnologyMerger().merge_matches(matches)
    assert len(merged) == 1
    assert merged[0].evidence_count == 2
    assert len(merged[0].matched_resources) == 2
    assert merged[0].confidence >= 80.0


def test_pipeline_emits_no_duplicate_technologies() -> None:
    """Detection pipeline should never emit duplicate technology IDs."""
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.RUNTIME_PATTERN,
            value="ReactDOM.createRoot",
            file="a.js",
            url="https://example.com/a.js",
        ),
        _evidence(
            evidence_type=EvidenceType.RUNTIME_PATTERN,
            value="useState",
            file="b.js",
            url="https://example.com/b.js",
        ),
        _evidence(evidence_type=EvidenceType.PACKAGE_REFERENCE, value="react", file="a.js"),
        _evidence(evidence_type=EvidenceType.PACKAGE_REFERENCE, value="react", file="b.js"),
    )
    result = EvidenceDetectionPipeline().detect(collection)
    react_matches = [item for item in result.detection.matches if item.technology.id == "react"]
    assert len(react_matches) == 1
    assert react_matches[0].evidence_count >= 2


def test_confidence_increases_with_independent_sources() -> None:
    """Confidence should increase when multiple evidence sources agree."""
    loader = TechnologySignatureLoader()
    react = next(item for item in loader.load_all() if item.id == "react")
    from techspecter.fingerprinting.detection.normalizer import normalize_evidence
    from techspecter.fingerprinting.detection.rules import RuleEvaluator

    single = _collection(
        _evidence(evidence_type=EvidenceType.STRING_LITERAL, value="usestate"),
    )
    multi = _collection(
        _evidence(evidence_type=EvidenceType.RUNTIME_PATTERN, value="ReactDOM.createRoot"),
        _evidence(evidence_type=EvidenceType.PACKAGE_REFERENCE, value="react"),
    )
    evaluator = RuleEvaluator()
    single_eval = evaluator.evaluate(react, normalize_evidence(single))
    multi_eval = evaluator.evaluate(react, normalize_evidence(multi))
    engine = ConfidenceEngine()
    single_score = engine.calculate(single_eval).final_confidence
    multi_score = engine.calculate(multi_eval).final_confidence
    assert multi_score > single_score
    assert (
        engine.calculate(multi_eval).correlation_bonus
        >= engine.calculate(single_eval).correlation_bonus
    )


def test_version_conflict_rejects_lower_priority() -> None:
    """Conflicting version candidates should reduce version confidence."""
    loader = TechnologySignatureLoader()
    react = next(item for item in loader.load_all() if item.id == "react")
    evidence = (
        _evidence(
            evidence_type=EvidenceType.PACKAGE_REFERENCE,
            value="react@19.1.0",
        ),
        _evidence(
            evidence_type=EvidenceType.BANNER,
            value="react@18.2.0",
            metadata={"origin": "banner"},
        ),
        _evidence(
            evidence_type=EvidenceType.RUNTIME_PATTERN,
            value="ReactDOM.createRoot",
        ),
    )
    from techspecter.fingerprinting.detection.normalizer import normalize_evidence
    from techspecter.fingerprinting.detection.rules import RuleEvaluator

    collection = _collection(*evidence)
    evaluation = RuleEvaluator().evaluate(react, normalize_evidence(collection))
    resolution = VersionResolutionEngine().resolve(
        react,
        evidence_items=collection.items,
        matched_rules=evaluation.matched_rules,
    )
    assert resolution.version in {"19.1.0", "18.2.0"}
    assert resolution.rejected_candidates


def test_normalize_version_rejects_invalid() -> None:
    """Invalid version strings should be rejected."""
    assert normalize_version("19.1.0") == "19.1.0"
    assert normalize_version("v19.1.0") == "19.1.0"
    assert normalize_version("not-a-version") is None


def test_manifest_version_candidate_extraction() -> None:
    """Manifest content should yield version candidates."""
    loader = TechnologySignatureLoader()
    nextjs = next(item for item in loader.load_all() if item.id == "nextjs")
    collection = _collection(
        _evidence(evidence_type=EvidenceType.RUNTIME_PATTERN, value="__NEXT_DATA__"),
        _evidence(
            evidence_type=EvidenceType.MANIFEST,
            value='{"nextVersion":"15.2.0","buildManifest":true}',
        ),
        _evidence(
            evidence_type=EvidenceType.VERSION_CANDIDATE,
            value="15.2.0",
            metadata={"origin": "manifest", "technology": "nextjs"},
        ),
    )
    from techspecter.fingerprinting.detection.normalizer import normalize_evidence
    from techspecter.fingerprinting.detection.rules import RuleEvaluator

    evaluation = RuleEvaluator().evaluate(nextjs, normalize_evidence(collection))
    resolution = VersionResolutionEngine().resolve(
        nextjs,
        evidence_items=collection.items,
        matched_rules=evaluation.matched_rules,
    )
    assert resolution.version == "15.2.0"


def test_source_map_package_path_version() -> None:
    """Source map paths with package@version should produce candidates."""
    loader = TechnologySignatureLoader()
    react = next(item for item in loader.load_all() if item.id == "react")
    evidence = (
        _evidence(
            evidence_type=EvidenceType.SOURCE_MAP_METADATA,
            value="node_modules/react@19.1.0/index.js",
            metadata={"origin": "sourcemap"},
        ),
        _evidence(evidence_type=EvidenceType.RUNTIME_PATTERN, value="ReactDOM.createRoot"),
    )
    collection = _collection(*evidence)
    candidates = VersionCandidateCollector().collect(
        react,
        evidence_items=collection.items,
        matched_evidence_ids=frozenset(item.id for item in collection.items),
        matched_resources=frozenset({"https://example.com/app.js"}),
    )
    assert any(item.version == "19.1.0" for item in candidates)


def test_runtime_version_extraction_metadata() -> None:
    """Technology-specific runtime patterns should link via metadata."""
    from techspecter.fingerprinting.javascript.extractors.versions import extract_version_candidates
    from techspecter.fingerprinting.javascript.models import JavaScriptResource

    resource = JavaScriptResource(
        content='React.version="19.1.0";',
        filename="app.js",
        url="https://example.com/app.js",
    )
    findings = extract_version_candidates(resource)
    assert any(item.matched_value == "19.1.0" for item in findings)
    assert any(item.metadata.get("technology") == "react" for item in findings)


def test_confidence_calibration_with_version_boost() -> None:
    """Known version with high confidence should boost detection confidence."""
    loader = TechnologySignatureLoader()
    react = next(item for item in loader.load_all() if item.id == "react")
    from techspecter.fingerprinting.detection.normalizer import normalize_evidence
    from techspecter.fingerprinting.detection.rules import RuleEvaluator

    collection = _collection(
        _evidence(evidence_type=EvidenceType.RUNTIME_PATTERN, value="ReactDOM.createRoot"),
        _evidence(evidence_type=EvidenceType.PACKAGE_REFERENCE, value="react"),
    )
    evaluation = RuleEvaluator().evaluate(react, normalize_evidence(collection))
    without = ConfidenceEngine().calculate(evaluation).final_confidence
    with_version = (
        ConfidenceEngine()
        .calculate(
            evaluation,
            version=VersionResolution(
                version="19.1.0",
                confidence=85.0,
                source="package",
                reason="test",
            ),
        )
        .final_confidence
    )
    assert with_version >= without
