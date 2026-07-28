"""Tests for explainable evidence-based detection engine."""

from __future__ import annotations

from datetime import UTC, datetime

from techspecter.fingerprinting.detection.pipeline import EvidenceDetectionPipeline
from techspecter.fingerprinting.detection.rules import RuleEvaluator
from techspecter.fingerprinting.detection.version_resolver import VersionResolutionEngine
from techspecter.fingerprinting.evidence.models import (
    Evidence,
    EvidenceCollection,
    EvidenceSource,
    EvidenceType,
)
from techspecter.fingerprinting.models import UNKNOWN_VERSION
from techspecter.fingerprinting.signatures.loader import TechnologySignatureLoader
from techspecter.fingerprinting.signatures.registry import SignatureRegistry


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


def test_signature_loader_loads_focused_technologies() -> None:
    """Loader should load expanded Phase 4 technology signatures."""
    signatures = TechnologySignatureLoader().load_all()
    ids = {item.id for item in signatures}
    assert "react" in ids
    assert "nextjs" in ids
    assert "angular" in ids
    assert len(signatures) >= 80


def test_detects_react_from_runtime_and_package_evidence() -> None:
    """React should be detected from combined runtime and package evidence."""
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.RUNTIME_PATTERN,
            value="ReactDOM.createRoot",
            metadata={"runtime_family": "react"},
        ),
        _evidence(evidence_type=EvidenceType.PACKAGE_REFERENCE, value="react"),
        _evidence(evidence_type=EvidenceType.VERSION_CANDIDATE, value="19.1.0"),
    )
    pipeline = EvidenceDetectionPipeline()
    result = pipeline.detect(collection)
    match = next((item for item in result.detection.matches if item.technology.id == "react"), None)
    assert match is not None
    assert match.confidence > 0
    assert match.evidence_count >= 2
    assert match.detection_reason


def test_detects_nextjs_with_react_dependency() -> None:
    """Next.js detection should include React dependency."""
    collection = _collection(
        _evidence(evidence_type=EvidenceType.RUNTIME_PATTERN, value="__NEXT_DATA__"),
        _evidence(
            evidence_type=EvidenceType.MANIFEST,
            value="buildManifest",
        ),
        _evidence(
            evidence_type=EvidenceType.RUNTIME_PATTERN,
            value="ReactDOM.createRoot",
            metadata={"runtime_family": "react"},
        ),
        _evidence(evidence_type=EvidenceType.PACKAGE_REFERENCE, value="react"),
    )
    result = EvidenceDetectionPipeline().detect(collection)
    ids = {item.technology.id for item in result.detection.matches}
    assert "nextjs" in ids
    assert "react" in ids


def test_angular_rejects_zone_js_only() -> None:
    """Angular should not be detected from zone.js alone."""
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.RUNTIME_PATTERN,
            value="zone.js",
            metadata={"runtime_family": "angular"},
        ),
    )
    result = EvidenceDetectionPipeline().detect(collection)
    assert not any(item.technology.id == "angular" for item in result.detection.matches)


def test_angular_detects_with_ivy_runtime() -> None:
    """Angular should be detected when Ivy runtime is present."""
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.RUNTIME_PATTERN,
            value="ɵɵdefineComponent",
            metadata={"runtime_family": "angular"},
        ),
        _evidence(evidence_type=EvidenceType.PACKAGE_REFERENCE, value="@angular/core"),
    )
    result = EvidenceDetectionPipeline().detect(collection)
    assert any(item.technology.id == "angular" for item in result.detection.matches)


def test_webpack_detects_bundle_runtime() -> None:
    """Webpack should be detected from bundle runtime evidence."""
    collection = _collection(
        _evidence(evidence_type=EvidenceType.BUNDLE_RUNTIME, value="__webpack_require__"),
    )
    result = EvidenceDetectionPipeline().detect(collection)
    assert any(item.technology.id == "webpack" for item in result.detection.matches)


def test_wordpress_detects_from_headers() -> None:
    """WordPress should be detected from HTTP header evidence."""
    collection = _collection(
        _evidence(
            evidence_type=EvidenceType.HTTP_HEADER,
            value="X-Powered-By: WordPress",
            source=EvidenceSource.NETWORK,
        ),
    )
    result = EvidenceDetectionPipeline().detect(collection)
    assert any(item.technology.id == "wordpress" for item in result.detection.matches)


def test_version_resolution_returns_unknown_without_candidates() -> None:
    """Version resolver should return Unknown when no candidates exist."""
    loader = TechnologySignatureLoader()
    react = next(item for item in loader.load_all() if item.id == "react")
    resolution = VersionResolutionEngine().resolve(react, evidence_items=(), matched_rules=())
    assert resolution.version == UNKNOWN_VERSION


def test_confidence_is_explainable() -> None:
    """Confidence breakdown should include component scores."""
    collection = _collection(
        _evidence(evidence_type=EvidenceType.RUNTIME_PATTERN, value="ReactDOM.createRoot"),
        _evidence(evidence_type=EvidenceType.PACKAGE_REFERENCE, value="react"),
    )
    result = EvidenceDetectionPipeline().detect(collection)
    assert "react" in result.scoring
    breakdown = result.scoring["react"]
    assert "evidence_score" in breakdown.components
    assert breakdown.final_confidence >= 0


def test_rule_evaluator_respects_minimum_score() -> None:
    """Weak evidence below minimum score should be rejected."""
    loader = TechnologySignatureLoader()
    react = next(item for item in loader.load_all() if item.id == "react")
    from techspecter.fingerprinting.detection.normalizer import normalize_evidence

    collection = _collection(
        _evidence(evidence_type=EvidenceType.FILENAME, value="app.js", file="app.js"),
    )
    normalized = normalize_evidence(collection)
    evaluation = RuleEvaluator().evaluate(react, normalized)
    assert evaluation.rejected


def test_custom_signature_plugin_via_registry() -> None:
    """Registry should accept plugin-provided signatures."""
    from techspecter.fingerprinting.signatures.models import SignatureRule, TechnologySignature

    registry = SignatureRegistry(loader=TechnologySignatureLoader())
    registry.register(
        TechnologySignature(
            id="custom-tech",
            name="Custom Tech",
            category="test",
            minimum_score=10.0,
            required_rules=(
                SignatureRule(
                    id="custom-req",
                    matcher="contains",
                    pattern="custom-marker",
                    target="content",
                    weight=10.0,
                ),
            ),
            positive_rules=(
                SignatureRule(
                    id="custom-pos",
                    matcher="contains",
                    pattern="custom-marker",
                    target="content",
                    weight=80.0,
                ),
            ),
        ),
    )
    collection = _collection(
        _evidence(evidence_type=EvidenceType.STRING_LITERAL, value="custom-marker")
    )
    pipeline = EvidenceDetectionPipeline(registry=registry)
    result = pipeline.detect(collection)
    assert any(item.technology.id == "custom-tech" for item in result.detection.matches)
