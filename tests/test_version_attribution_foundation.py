"""Phase 6 Step 1 foundation: version evidence attribution regression tests."""

from __future__ import annotations

from techspecter.fingerprinting.detection.models import RuleMatch, VersionResolution
from techspecter.fingerprinting.detection.version.candidates import VersionCandidateCollector
from techspecter.fingerprinting.detection.version_resolver import VersionResolutionEngine
from techspecter.fingerprinting.evidence.models import Evidence, EvidenceSource, EvidenceType
from techspecter.fingerprinting.models import UNKNOWN_VERSION
from techspecter.fingerprinting.signatures.loader import TechnologySignatureLoader
from techspecter.fingerprinting.signatures.models import SignatureRule
from techspecter.versioning.attribution import (
    confirm_or_keep_candidate,
    independent_confidence_axes,
)
from techspecter.versioning.models import (
    VersionAttributionState,
    VersionOwnershipClass,
)
from techspecter.versioning.ownership import (
    classify_version_evidence_ownership,
    ownership_supports_confirmation,
)


def _signatures() -> dict[str, object]:
    return {item.id: item for item in TechnologySignatureLoader().load_all()}


def _rule_match(signature_id: str, evidence: Evidence) -> RuleMatch:
    return RuleMatch(
        rule=SignatureRule(
            id=f"{signature_id}-rule",
            matcher="string",
            pattern="test",
            weight=10.0,
        ),
        evidence=evidence,
        matched_text=evidence.matched_value or "",
        weight=10.0,
    )


def test_strong_owned_version_evidence_confirms() -> None:
    """Strong technology-owned version evidence confirms a version."""
    signatures = _signatures()
    react = signatures["react"]
    evidence = Evidence(
        id="react-version",
        source=EvidenceSource.JAVASCRIPT,
        evidence_type=EvidenceType.VERSION_CANDIDATE,
        matched_value="19.3.0-canary-test",
        matched_pattern=r'reconcilerVersion\s*:\s*"([^"]+)"',
        collector="javascript-analyzer",
        metadata={"technology": "react", "origin": "runtime"},
        url="https://example.com/bundle.js",
        file="bundle.js",
    )
    resolution = VersionResolutionEngine().resolve(
        react,
        evidence_items=(evidence,),
        matched_rules=(_rule_match("react", evidence),),
        technology_confidence=100.0,
    )
    assert resolution.version == "19.3.0-canary-test"
    assert resolution.attribution_state == VersionAttributionState.CONFIRMED.value
    assert resolution.ownership_class == VersionOwnershipClass.OWNED.value
    assert resolution.ownership_confidence >= 65.0
    assert resolution.technology_confidence == 100.0
    assert resolution.version_confidence > 0.0


def test_weak_value_hint_ownership_stays_candidate_only() -> None:
    """Weak token-in-value ownership must not auto-confirm a version."""
    signatures = _signatures()
    react = signatures["react"]
    # Ownership comes from "react" token in matched_value; version lives in metadata.
    evidence = Evidence(
        id="weak-hint",
        source=EvidenceSource.JAVASCRIPT,
        evidence_type=EvidenceType.VERSION_CANDIDATE,
        matched_value="react-compat-shim",
        collector="javascript-analyzer",
        metadata={"origin": "content", "version": "18.2.0"},
        url="https://example.com/bundle.js",
    )
    assessment = classify_version_evidence_ownership("react", evidence)
    assert assessment.ownership_class == VersionOwnershipClass.OWNED
    assert assessment.basis == "value_hint"
    assert not ownership_supports_confirmation(assessment)

    resolution = VersionResolutionEngine().resolve(
        react,
        evidence_items=(evidence,),
        matched_rules=(),
        technology_confidence=100.0,
    )
    assert resolution.version == UNKNOWN_VERSION
    assert resolution.attribution_state == VersionAttributionState.CANDIDATE.value
    assert resolution.candidate_count >= 1
    assert resolution.technology_confidence == 100.0


def test_technology_and_version_confidence_are_independent() -> None:
    """Technology confidence and version confidence are separate axes."""
    axes = independent_confidence_axes(
        technology_confidence=100.0,
        version_confidence=0.0,
        ownership_confidence=0.0,
    )
    assert axes["technology_confidence"] == 100.0
    assert axes["version_confidence"] == 0.0
    assert axes["ownership_confidence"] == 0.0

    state = confirm_or_keep_candidate(
        classify_version_evidence_ownership(
            "react",
            Evidence(
                source=EvidenceSource.JAVASCRIPT,
                evidence_type=EvidenceType.VERSION_CANDIDATE,
                matched_value="1.2.3",
                collector="test",
                metadata={},
            ),
        ),
        version_confidence=90.0,
    )
    assert state != VersionAttributionState.CONFIRMED


def test_technology_confirmed_without_version_is_valid() -> None:
    """A confirmed technology may legitimately have Unknown version."""
    signatures = _signatures()
    turbopack = signatures["turbopack"]
    marker = Evidence(
        id="turbopack-marker",
        source=EvidenceSource.JAVASCRIPT,
        evidence_type=EvidenceType.RUNTIME_PATTERN,
        matched_value="TURBOPACK",
        collector="javascript-analyzer",
        metadata={"technology": "turbopack"},
        url="https://example.com/bundle.js",
    )
    resolution = VersionResolutionEngine().resolve(
        turbopack,
        evidence_items=(marker,),
        matched_rules=(_rule_match("turbopack", marker),),
        technology_confidence=95.0,
    )
    assert resolution.version == UNKNOWN_VERSION
    assert resolution.technology_confidence == 95.0


def test_multi_technology_bundle_keeps_independent_ownership() -> None:
    """Shared bundle versions do not transfer across technologies."""
    signatures = _signatures()
    react_evidence = Evidence(
        id="react-version",
        source=EvidenceSource.JAVASCRIPT,
        evidence_type=EvidenceType.VERSION_CANDIDATE,
        matched_value="19.3.0-canary-test",
        matched_pattern=r'reconcilerVersion:"([^"]+)"',
        collector="javascript-analyzer",
        metadata={"technology": "react"},
        url="https://example.com/bundle.js",
        file="bundle.js",
    )
    next_marker = Evidence(
        id="next-marker",
        source=EvidenceSource.JAVASCRIPT,
        evidence_type=EvidenceType.RUNTIME_PATTERN,
        matched_value="window.next",
        collector="javascript-analyzer",
        metadata={"technology": "nextjs"},
        url="https://example.com/bundle.js",
        file="bundle.js",
    )
    turbo_marker = Evidence(
        id="turbo-marker",
        source=EvidenceSource.JAVASCRIPT,
        evidence_type=EvidenceType.RUNTIME_PATTERN,
        matched_value="TURBOPACK",
        collector="javascript-analyzer",
        metadata={"technology": "turbopack"},
        url="https://example.com/bundle.js",
        file="bundle.js",
    )
    items = (react_evidence, next_marker, turbo_marker)
    engine = VersionResolutionEngine()

    react_resolution = engine.resolve(
        signatures["react"],
        evidence_items=items,
        matched_rules=(_rule_match("react", react_evidence),),
        technology_confidence=100.0,
    )
    next_resolution = engine.resolve(
        signatures["nextjs"],
        evidence_items=items,
        matched_rules=(_rule_match("nextjs", next_marker),),
        technology_confidence=90.0,
    )
    turbo_resolution = engine.resolve(
        signatures["turbopack"],
        evidence_items=items,
        matched_rules=(_rule_match("turbopack", turbo_marker),),
        technology_confidence=90.0,
    )

    assert react_resolution.version == "19.3.0-canary-test"
    assert react_resolution.attribution_state == VersionAttributionState.CONFIRMED.value
    assert next_resolution.version == UNKNOWN_VERSION
    assert turbo_resolution.version == UNKNOWN_VERSION


def test_version_candidate_preserves_provenance_chain() -> None:
    """Collected candidates retain technology/asset/evidence/pattern provenance."""
    signatures = _signatures()
    evidence = Evidence(
        id="react-version",
        source=EvidenceSource.JAVASCRIPT,
        evidence_type=EvidenceType.VERSION_CANDIDATE,
        matched_value="19.3.0-canary-test",
        matched_pattern=r'reconcilerVersion:"([^"]+)"',
        collector="javascript-analyzer",
        metadata={"technology": "react"},
        url="https://example.com/bundle.js",
        file="bundle.js",
    )
    candidates = VersionCandidateCollector().collect(
        signatures["react"],
        evidence_items=(evidence,),
        matched_evidence_ids=frozenset({evidence.id}),
        technology_confidence=100.0,
    )
    assert candidates
    candidate = candidates[0]
    assert candidate.technology_id == "react"
    assert candidate.evidence_id == "react-version"
    assert candidate.source_url == "https://example.com/bundle.js"
    assert candidate.source_file == "bundle.js"
    assert candidate.matched_pattern == evidence.matched_pattern
    assert candidate.matched_value == "19.3.0-canary-test"
    assert candidate.ownership_class == VersionOwnershipClass.OWNED
    assert candidate.attribution_state == VersionAttributionState.CANDIDATE
    assert candidate.technology_confidence == 100.0
    assert candidate.version_confidence > 0.0


def test_mismatched_metadata_technology_is_incidental() -> None:
    """Evidence tagged for one technology is incidental for another."""
    evidence = Evidence(
        source=EvidenceSource.JAVASCRIPT,
        evidence_type=EvidenceType.VERSION_CANDIDATE,
        matched_value="19.3.0",
        collector="javascript-analyzer",
        metadata={"technology": "react"},
    )
    assessment = classify_version_evidence_ownership("turbopack", evidence)
    assert assessment.ownership_class == VersionOwnershipClass.INCIDENTAL
    assert not ownership_supports_confirmation(assessment)


def test_resolution_exposes_candidate_provenance_when_unconfirmed() -> None:
    """Unresolved weak evidence remains inspectable as candidates."""
    signatures = _signatures()
    evidence = Evidence(
        id="weak-hint",
        source=EvidenceSource.JAVASCRIPT,
        evidence_type=EvidenceType.VERSION_CANDIDATE,
        matched_value="react-compat-shim",
        collector="javascript-analyzer",
        metadata={"origin": "content", "version": "18.2.0"},
        url="https://example.com/bundle.js",
    )
    resolution = VersionResolutionEngine().resolve(
        signatures["react"],
        evidence_items=(evidence,),
        matched_rules=(),
    )
    assert isinstance(resolution, VersionResolution)
    assert resolution.version == UNKNOWN_VERSION
    assert resolution.candidates
    assert all(getattr(item, "technology_id", None) == "react" for item in resolution.candidates)
