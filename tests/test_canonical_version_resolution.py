"""Phase 6 Step 3: canonical resolution across JS and evidence paths."""

from __future__ import annotations

from techspecter.fingerprinting.detection.version.candidates import VersionCandidate
from techspecter.fingerprinting.models import UNKNOWN_VERSION, Technology, TechnologyMatch
from techspecter.technology_intelligence.attribution import AssetAttributor
from techspecter.technology_intelligence.evidence import build_version_attribution
from techspecter.versioning.adapters import (
    extracted_versions_to_candidates,
    resolve_extracted_versions,
    technology_version_result_from_resolution,
)
from techspecter.versioning.engine import JavaScriptResourceContent, VersionDetectionEngine
from techspecter.versioning.models import (
    ExtractedVersion,
    VersionAttributionState,
    VersionConfidenceLevel,
    VersionConflictClass,
    VersionEvidence,
    VersionEvidenceType,
    VersionOwnershipClass,
)
from techspecter.versioning.resolution import resolve_primary_version


def _extracted(
    version: str,
    *,
    method: VersionEvidenceType = VersionEvidenceType.RUNTIME_CONSTANT,
    url: str = "https://example.com/a.js",
    filename: str = "a.js",
    confidence: float = 95.0,
    extractor_id: str = "tech-a-extractor",
) -> ExtractedVersion:
    return ExtractedVersion(
        version=version,
        confidence=confidence,
        confidence_level=VersionConfidenceLevel.HIGH,
        method=method,
        evidence=[
            VersionEvidence(
                evidence_type=method,
                matched_value=version,
                pattern=r"version",
                source_url=url,
                filename=filename,
                ownership_class=VersionOwnershipClass.OWNED,
                ownership_confidence=95.0,
            ),
        ],
        extractor_id=extractor_id,
        source_url=url,
        filename=filename,
        technology_id="tech-a",
        ownership_class=VersionOwnershipClass.OWNED,
        ownership_confidence=95.0,
        matched_pattern=r"version",
        matched_value=version,
    )


def test_js_extractor_output_feeds_canonical_candidates() -> None:
    candidates = extracted_versions_to_candidates(
        [_extracted("1.2.3")],
        technology_id="tech-a",
    )
    assert len(candidates) == 1
    assert isinstance(candidates[0], VersionCandidate)
    assert candidates[0].technology_id == "tech-a"
    assert candidates[0].version == "1.2.3"
    assert candidates[0].ownership_class == VersionOwnershipClass.OWNED
    assert candidates[0].attribution_state == VersionAttributionState.CANDIDATE
    assert candidates[0].source == "runtime"


def test_js_extractor_uses_canonical_resolver_not_raw_sort() -> None:
    outcome = resolve_extracted_versions(
        [
            _extracted(
                "1.0.0",
                method=VersionEvidenceType.GENERIC_LITERAL,
                confidence=55.0,
                url="https://example.com/weak.js",
            ),
            _extracted(
                "1.2.0",
                method=VersionEvidenceType.PACKAGE_IDENTIFIER,
                confidence=90.0,
                url="https://example.com/pkg.js",
            ),
        ],
        technology_id="tech-a",
    )
    assert outcome.primary_version == "1.2.0"
    assert outcome.conflict_class in {
        VersionConflictClass.NO_CONFLICT,
        VersionConflictClass.WEAK_ALTERNATE,
    }


def test_js_strong_owned_evidence_confirms_via_engine() -> None:
    engine = VersionDetectionEngine()
    resources = [
        JavaScriptResourceContent(
            url="https://example.com/react.js",
            filename="react.js",
            content='reconcilerVersion:"19.3.0-canary-test";rendererPackageName:"react-dom";',
        ),
    ]
    result = engine.detect_for_technology("react", resources)
    assert result is not None
    assert result.version == "19.3.0-canary-test"
    assert result.attribution_state == VersionAttributionState.CONFIRMED
    assert result.conflict_class is not None


def test_js_conflicting_strong_candidates_can_be_ambiguous() -> None:
    outcome = resolve_extracted_versions(
        [
            _extracted(
                "2.0.0",
                method=VersionEvidenceType.PACKAGE_IDENTIFIER,
                url="https://example.com/a.js",
            ),
            _extracted(
                "1.9.0",
                method=VersionEvidenceType.PACKAGE_IDENTIFIER,
                url="https://example.com/b.js",
            ),
        ],
        technology_id="tech-a",
    )
    assert outcome.primary_version == UNKNOWN_VERSION
    assert set(outcome.alternate_versions) == {"1.9.0", "2.0.0"}


def test_js_and_evidence_candidates_share_resolver_semantics() -> None:
    js_candidates = extracted_versions_to_candidates(
        [_extracted("3.1.0", method=VersionEvidenceType.PACKAGE_IDENTIFIER)],
        technology_id="tech-a",
    )
    evidence_like = (
        VersionCandidate(
            version="3.0.0",
            source="content",
            priority=55.0,
            technology_id="tech-a",
            evidence_id="ev-weak",
            source_url="https://example.com/ref.js",
            ownership_class=VersionOwnershipClass.OWNED,
            ownership_confidence=55.0,
            version_confidence=55.0,
        ),
    )
    outcome = resolve_primary_version((*js_candidates, *evidence_like))
    assert outcome.primary_version == "3.1.0"


def test_same_source_repetition_does_not_inflate_js_corroboration() -> None:
    extracted = [
        _extracted("4.0.0", url="https://example.com/one.js", filename="one.js")
        for _ in range(15)
    ]
    outcome = resolve_extracted_versions(extracted, technology_id="tech-a")
    assert outcome.primary_version == "4.0.0"
    assert outcome.independent_source_count == 1


def test_independent_js_assets_corroborate() -> None:
    extracted = [
        _extracted("5.0.0", url="https://example.com/a.js", filename="a.js"),
        _extracted("5.0.0", url="https://example.com/b.js", filename="b.js"),
        _extracted("5.0.0", url="https://example.com/c.js", filename="c.js"),
    ]
    outcome = resolve_extracted_versions(extracted, technology_id="tech-a")
    assert outcome.primary_version == "5.0.0"
    assert outcome.independent_source_count == 3


def test_technology_intelligence_prefers_match_over_independent_js_result() -> None:
    match = TechnologyMatch(
        technology=Technology(id="react", name="React", category="javascript-framework"),
        version="19.3.0-canary-test",
        confidence=98.0,
        version_confidence=92.0,
        version_reason="Canonical primary",
        alternate_versions=["18.2.0"],
    )
    # Simulate a divergent JS extractor result that must not override the match.
    divergent = technology_version_result_from_resolution(
        technology_id="react",
        extracted=[_extracted("18.0.0")],
        outcome=resolve_extracted_versions(
            [_extracted("18.0.0")],
            technology_id="react",
        ),
    )
    assert divergent is not None
    assert divergent.version != match.version

    attr = build_version_attribution(match, None, attributor=AssetAttributor())
    assert attr is not None
    assert attr.detected_version == match.version
    assert attr.alternative_candidates == ["18.2.0"]


def test_invalid_js_versions_cannot_bypass_canonical_validation() -> None:
    extracted = [
        ExtractedVersion(
            version="0.0.0",
            confidence=99.0,
            confidence_level=VersionConfidenceLevel.HIGH,
            method=VersionEvidenceType.RUNTIME_CONSTANT,
            evidence=[],
            extractor_id="x",
            source_url="https://example.com/bad.js",
            filename="bad.js",
            ownership_class=VersionOwnershipClass.OWNED,
            ownership_confidence=95.0,
        ),
        _extracted("6.1.0"),
    ]
    outcome = resolve_extracted_versions(extracted, technology_id="tech-a")
    assert outcome.primary_version == "6.1.0"
    assert "0.0.0" not in outcome.alternate_versions
