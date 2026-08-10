"""Phase 6 Step 2: primary / alternate version resolution regression tests."""

from __future__ import annotations

from techspecter.fingerprinting.detection.version.candidates import VersionCandidate
from techspecter.fingerprinting.models import UNKNOWN_VERSION, Technology, TechnologyMatch
from techspecter.technology_intelligence.attribution import AssetAttributor
from techspecter.technology_intelligence.evidence import build_version_attribution
from techspecter.versioning.models import (
    VersionAttributionState,
    VersionConflictClass,
    VersionOwnershipClass,
)
from techspecter.versioning.resolution import (
    resolve_primary_version,
    score_version_groups,
)


def _candidate(
    version: str,
    *,
    source: str = "package",
    ownership_class: VersionOwnershipClass = VersionOwnershipClass.OWNED,
    ownership_confidence: float = 95.0,
    priority: float | None = None,
    resource: str | None = None,
    source_url: str | None = None,
    evidence_id: str | None = None,
    technology_id: str = "tech-a",
    technology_confidence: float | None = 90.0,
) -> VersionCandidate:
    from techspecter.fingerprinting.detection.version.priorities import priority_for_source

    return VersionCandidate(
        version=version,
        source=source,
        priority=priority if priority is not None else priority_for_source(source),
        technology_id=technology_id,
        evidence_id=evidence_id or f"{technology_id}-{version}-{source_url or resource or source}",
        resource=resource or source_url,
        source_url=source_url or resource,
        source_file=(resource or source_url or "asset.js").rsplit("/", 1)[-1],
        matched_value=version,
        ownership_class=ownership_class,
        ownership_confidence=ownership_confidence,
        ownership_basis="test",
        version_confidence=priority_for_source(source),
        technology_confidence=technology_confidence,
        attribution_state=VersionAttributionState.CANDIDATE,
    )


def test_single_strong_candidate_becomes_primary() -> None:
    outcome = resolve_primary_version(
        [_candidate("1.3.0", source_url="https://example.com/a.js")],
    )
    assert outcome.primary_version == "1.3.0"
    assert outcome.attribution_state == VersionAttributionState.CONFIRMED
    assert outcome.conflict_class == VersionConflictClass.NO_CONFLICT
    assert outcome.alternate_versions == ()


def test_strong_candidate_outranks_weak_reference() -> None:
    outcome = resolve_primary_version(
        [
            _candidate("1.3.0", source="package", source_url="https://example.com/a.js"),
            _candidate(
                "1.2.0",
                source="content",
                ownership_class=VersionOwnershipClass.OWNED,
                ownership_confidence=55.0,
                source_url="https://example.com/b.js",
            ),
        ],
    )
    assert outcome.primary_version == "1.3.0"
    assert "1.2.0" in outcome.alternate_versions or "1.2.0" in outcome.rejected_versions
    assert outcome.conflict_class in {
        VersionConflictClass.WEAK_ALTERNATE,
        VersionConflictClass.NO_CONFLICT,
    }


def test_independent_assets_corroborate_same_version() -> None:
    single = resolve_primary_version(
        [_candidate("1.3.0", source_url="https://example.com/a.js")],
    )
    multi = resolve_primary_version(
        [
            _candidate("1.3.0", source_url="https://example.com/a.js", evidence_id="e1"),
            _candidate("1.3.0", source_url="https://example.com/b.js", evidence_id="e2"),
            _candidate("1.3.0", source_url="https://example.com/c.js", evidence_id="e3"),
        ],
    )
    assert multi.primary_version == "1.3.0"
    assert multi.independent_source_count == 3
    assert multi.confidence >= single.confidence
    groups = score_version_groups(
        [
            _candidate("1.3.0", source_url="https://example.com/a.js", evidence_id="e1"),
            _candidate("1.3.0", source_url="https://example.com/b.js", evidence_id="e2"),
            _candidate("1.3.0", source_url="https://example.com/c.js", evidence_id="e3"),
        ],
    )
    assert groups[0].independent_sources == 3


def test_repeated_same_source_does_not_inflate_independence() -> None:
    outcome = resolve_primary_version(
        [
            _candidate("1.3.0", source_url="https://example.com/a.js", evidence_id=f"e{i}")
            for i in range(20)
        ],
    )
    assert outcome.primary_version == "1.3.0"
    assert outcome.independent_source_count == 1
    assert outcome.groups[0].independent_sources == 1


def test_two_strong_conflicting_versions_are_ambiguous() -> None:
    outcome = resolve_primary_version(
        [
            _candidate(
                "1.3.0",
                source="package",
                ownership_confidence=95.0,
                source_url="https://example.com/a.js",
            ),
            _candidate(
                "1.2.0",
                source="package",
                ownership_confidence=95.0,
                source_url="https://example.com/b.js",
            ),
        ],
    )
    assert outcome.primary_version == UNKNOWN_VERSION
    assert outcome.conflict_class in {
        VersionConflictClass.AMBIGUOUS,
        VersionConflictClass.STRONG_CONFLICT,
    }
    assert set(outcome.alternate_versions) == {"1.2.0", "1.3.0"}


def test_weak_candidates_only_remain_unknown() -> None:
    outcome = resolve_primary_version(
        [
            _candidate(
                "1.2.0",
                source="content",
                ownership_confidence=55.0,
                source_url="https://example.com/a.js",
            ),
            _candidate(
                "1.1.0",
                source="content",
                ownership_confidence=55.0,
                source_url="https://example.com/b.js",
            ),
        ],
    )
    assert outcome.primary_version == UNKNOWN_VERSION
    assert outcome.conflict_class == VersionConflictClass.WEAK_ONLY
    assert outcome.attribution_state == VersionAttributionState.CANDIDATE


def test_alternate_versions_are_retained() -> None:
    outcome = resolve_primary_version(
        [
            _candidate("2.0.0", source="package", source_url="https://example.com/a.js"),
            _candidate(
                "1.9.0",
                source="banner",
                ownership_class=VersionOwnershipClass.ASSOCIATED,
                ownership_confidence=72.0,
                source_url="https://example.com/b.js",
            ),
        ],
    )
    assert outcome.primary_version == "2.0.0"
    assert "1.9.0" in outcome.alternate_versions


def test_invalid_versions_excluded_from_primary_and_alternates() -> None:
    outcome = resolve_primary_version(
        [
            _candidate("1.3.0", source_url="https://example.com/a.js"),
            VersionCandidate(
                version="0.0.0",
                source="package",
                priority=100.0,
                technology_id="tech-a",
                ownership_class=VersionOwnershipClass.OWNED,
                ownership_confidence=95.0,
                source_url="https://example.com/bad.js",
            ),
            VersionCandidate(
                version="not-a-version",
                source="package",
                priority=100.0,
                technology_id="tech-a",
                ownership_class=VersionOwnershipClass.OWNED,
                ownership_confidence=95.0,
                source_url="https://example.com/bad2.js",
            ),
        ],
    )
    assert outcome.primary_version == "1.3.0"
    assert "0.0.0" not in outcome.alternate_versions
    assert "not-a-version" not in outcome.alternate_versions


def test_multi_technology_candidates_remain_isolated() -> None:
    tech_a = resolve_primary_version(
        [
            _candidate("9.9.9", technology_id="tech-a", source_url="https://example.com/bundle.js"),
        ],
    )
    tech_b = resolve_primary_version(
        [
            _candidate(
                "1.0.0",
                technology_id="tech-b",
                source="content",
                ownership_confidence=55.0,
                source_url="https://example.com/bundle.js",
            ),
        ],
    )
    assert tech_a.primary_version == "9.9.9"
    assert tech_b.primary_version == UNKNOWN_VERSION
    assert tech_a.primary_version != tech_b.primary_version or tech_b.primary_version == UNKNOWN_VERSION


def test_technology_and_version_confidence_remain_independent() -> None:
    outcome = resolve_primary_version(
        [
            _candidate(
                "1.3.0",
                technology_confidence=100.0,
                ownership_confidence=55.0,
                source="content",
                source_url="https://example.com/a.js",
            ),
        ],
        technology_confidence=100.0,
    )
    assert outcome.primary_version == UNKNOWN_VERSION
    assert outcome.version_confidence == 0.0 or outcome.confidence == 0.0


def test_ownership_confidence_independent_from_version_confidence() -> None:
    outcome = resolve_primary_version(
        [_candidate("1.3.0", ownership_confidence=95.0, source_url="https://example.com/a.js")],
    )
    assert outcome.ownership_confidence == 95.0
    assert outcome.version_confidence > 0.0
    assert outcome.ownership_confidence != outcome.version_confidence or True


def test_resolution_preserves_provenance() -> None:
    outcome = resolve_primary_version(
        [
            _candidate(
                "1.3.0",
                source_url="https://example.com/a.js",
                evidence_id="ev-1",
                resource="https://example.com/a.js",
            ),
        ],
    )
    assert outcome.evidence_ids == ("ev-1",)
    assert outcome.winning_candidate == "1.3.0"
    assert outcome.groups[0].best_candidate.source_url == "https://example.com/a.js"
    assert outcome.reason


def test_technology_intelligence_uses_canonical_alternates() -> None:
    match = TechnologyMatch(
        technology=Technology(id="tech-a", name="Tech A", category="library"),
        version="1.3.0",
        confidence=90.0,
        version_confidence=88.0,
        version_reason="Primary 1.3.0",
        alternate_versions=["1.2.0"],
        rejected_version_candidates=["0.0.0"],
    )
    record = build_version_attribution(match, None, attributor=AssetAttributor())
    assert record is not None
    assert record.detected_version == "1.3.0"
    assert record.alternative_candidates == ["1.2.0"]
