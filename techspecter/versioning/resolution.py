"""Generic primary / alternate version resolution (Phase 6 Step 2).

Ranks technology-scoped version candidates using ownership, evidence quality,
and independent-source corroboration. Does not prefer newer numeric versions.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from techspecter.fingerprinting.detection.version.candidates import (
    VersionCandidate,
    candidate_supports_confirmation,
)
from techspecter.fingerprinting.detection.version.priorities import priority_for_source
from techspecter.fingerprinting.models import UNKNOWN_VERSION
from techspecter.versioning.models import (
    VersionAttributionState,
    VersionConflictClass,
    VersionOwnershipClass,
)
from techspecter.versioning.validator import is_valid_version

# Clear-win margin between the top two strong version groups.
_STRONG_MARGIN = 12.0
# Maximum corroboration bonus from independent assets.
_MAX_CORROBORATION = 20.0
_CORROBORATION_PER_SOURCE = 8.0


@dataclass(frozen=True, slots=True)
class VersionGroupScore:
    """Aggregated score for one normalized version string."""

    version: str
    score: float
    ownership_confidence: float
    independent_sources: int
    confirmable: bool
    evidence_ids: tuple[str, ...]
    source_keys: tuple[str, ...]
    best_candidate: VersionCandidate
    reason: str


@dataclass(frozen=True, slots=True)
class PrimaryVersionResolution:
    """Canonical technology-scoped version resolution outcome."""

    primary_version: str
    alternate_versions: tuple[str, ...] = ()
    rejected_versions: tuple[str, ...] = ()
    conflict_class: VersionConflictClass = VersionConflictClass.NO_CONFLICT
    attribution_state: VersionAttributionState = VersionAttributionState.CANDIDATE
    confidence: float = 0.0
    version_confidence: float = 0.0
    ownership_confidence: float = 0.0
    ownership_class: str | None = None
    source: str = "none"
    reason: str = ""
    evidence_ids: tuple[str, ...] = ()
    independent_source_count: int = 0
    candidate_count: int = 0
    winning_candidate: str | None = None
    groups: tuple[VersionGroupScore, ...] = ()


def source_identity(candidate: VersionCandidate) -> str:
    """Return a stable identity for independent-source corroboration."""
    for value in (
        candidate.source_url,
        candidate.resource,
        candidate.asset_id,
        candidate.source_file,
        candidate.evidence_id,
    ):
        if value:
            return str(value)
    return f"{candidate.source}:{candidate.version}"


def score_version_groups(
    candidates: tuple[VersionCandidate, ...] | list[VersionCandidate],
) -> list[VersionGroupScore]:
    """Group candidates by version and score each group."""
    by_version: dict[str, list[VersionCandidate]] = defaultdict(list)
    for candidate in candidates:
        if not is_valid_version(candidate.version):
            continue
        by_version[candidate.version].append(candidate)

    groups: list[VersionGroupScore] = []
    for version, items in by_version.items():
        groups.append(_score_group(version, items))
    groups.sort(key=lambda item: (-item.score, -item.ownership_confidence, item.version))
    return groups


def resolve_primary_version(
    candidates: tuple[VersionCandidate, ...] | list[VersionCandidate],
    *,
    technology_confidence: float | None = None,
) -> PrimaryVersionResolution:
    """Resolve primary/alternate versions for one technology.

    Technology confidence is accepted for provenance only and never drives
    version selection.
    """
    _ = technology_confidence
    candidate_tuple = tuple(candidates)
    if not candidate_tuple:
        return PrimaryVersionResolution(
            primary_version=UNKNOWN_VERSION,
            reason="No version candidates matched technology context",
            attribution_state=VersionAttributionState.CANDIDATE,
            conflict_class=VersionConflictClass.WEAK_ONLY,
        )

    valid = [item for item in candidate_tuple if is_valid_version(item.version)]
    invalid = sorted({item.version for item in candidate_tuple if not is_valid_version(item.version)})
    if not valid:
        return PrimaryVersionResolution(
            primary_version=UNKNOWN_VERSION,
            rejected_versions=tuple(invalid),
            reason="All version candidates were invalid or placeholder values",
            attribution_state=VersionAttributionState.REJECTED,
            conflict_class=VersionConflictClass.WEAK_ONLY,
            candidate_count=len(candidate_tuple),
        )

    groups = score_version_groups(valid)
    strong = [group for group in groups if group.confirmable]
    weak = [group for group in groups if not group.confirmable]

    if not strong:
        best_weak = groups[0]
        alternates = tuple(group.version for group in groups[1:4])
        return PrimaryVersionResolution(
            primary_version=UNKNOWN_VERSION,
            alternate_versions=alternates,
            rejected_versions=tuple(invalid),
            conflict_class=VersionConflictClass.WEAK_ONLY,
            attribution_state=VersionAttributionState.CANDIDATE,
            confidence=0.0,
            version_confidence=best_weak.best_candidate.version_confidence,
            ownership_confidence=best_weak.ownership_confidence,
            ownership_class=best_weak.best_candidate.ownership_class.value,
            source=best_weak.best_candidate.source,
            reason=(
                "Only weak/reference version evidence available; "
                "no primary version confirmed"
            ),
            evidence_ids=_merge_evidence_ids(groups),
            independent_source_count=best_weak.independent_sources,
            candidate_count=len(candidate_tuple),
            groups=tuple(groups),
        )

    top = strong[0]
    runner_up = strong[1] if len(strong) > 1 else None

    if runner_up is not None and (top.score - runner_up.score) < _STRONG_MARGIN:
        strong_sources: set[str] = set()
        for group in strong:
            strong_sources.update(group.source_keys)
        # Multiple methods in one asset are ranked by evidence quality, not treated
        # as independent cross-asset conflicts.
        if len(strong_sources) > 1:
            alternates = tuple(group.version for group in strong)
            return PrimaryVersionResolution(
                primary_version=UNKNOWN_VERSION,
                alternate_versions=alternates,
                rejected_versions=tuple(
                    sorted({*invalid, *(group.version for group in weak)}),
                ),
                conflict_class=(
                    VersionConflictClass.AMBIGUOUS
                    if abs(top.score - runner_up.score) < (_STRONG_MARGIN / 2)
                    else VersionConflictClass.STRONG_CONFLICT
                ),
                attribution_state=VersionAttributionState.CANDIDATE,
                confidence=0.0,
                version_confidence=0.0,
                ownership_confidence=max(top.ownership_confidence, runner_up.ownership_confidence),
                ownership_class=top.best_candidate.ownership_class.value,
                source=top.best_candidate.source,
                reason=(
                    "Strong conflicting version evidence without a clear ownership/"
                    f"quality margin ({top.version} score={top.score:.1f} vs "
                    f"{runner_up.version} score={runner_up.score:.1f})"
                ),
                evidence_ids=_merge_evidence_ids(strong),
                independent_source_count=max(
                    top.independent_sources,
                    runner_up.independent_sources,
                ),
                candidate_count=len(candidate_tuple),
                groups=tuple(groups),
            )

    alternates = tuple(
        group.version
        for group in (*strong[1:], *weak)
        if group.version != top.version
        and _retain_as_alternate(group)
    )
    conflict = (
        VersionConflictClass.WEAK_ALTERNATE
        if weak or len(strong) > 1
        else VersionConflictClass.NO_CONFLICT
    )
    confidence = _final_confidence(top)
    reason = _primary_reason(top, conflict, alternates)

    return PrimaryVersionResolution(
        primary_version=top.version,
        alternate_versions=alternates,
        rejected_versions=tuple(
            sorted(
                {
                    *invalid,
                    *(
                        group.version
                        for group in groups
                        if group.version != top.version and group.version not in alternates
                    ),
                },
            ),
        ),
        conflict_class=conflict,
        attribution_state=VersionAttributionState.CONFIRMED,
        confidence=confidence,
        version_confidence=confidence,
        ownership_confidence=top.ownership_confidence,
        ownership_class=top.best_candidate.ownership_class.value,
        source=top.best_candidate.source,
        reason=reason,
        evidence_ids=top.evidence_ids,
        independent_source_count=top.independent_sources,
        candidate_count=len(candidate_tuple),
        winning_candidate=top.version,
        groups=tuple(groups),
    )


def _score_group(version: str, items: list[VersionCandidate]) -> VersionGroupScore:
    confirmable_items = [item for item in items if candidate_supports_confirmation(item)]
    ranked_items = confirmable_items or items
    best = max(
        ranked_items,
        key=lambda item: (
            item.ownership_confidence,
            item.priority,
            item.version_confidence,
        ),
    )
    source_keys = tuple(sorted({source_identity(item) for item in ranked_items}))
    independent = len(source_keys)
    ownership = max(item.ownership_confidence for item in ranked_items)
    confirmable = bool(confirmable_items)

    score = best.priority * 0.50
    score += ownership * 0.35
    if independent > 1:
        score += min(
            _MAX_CORROBORATION,
            (independent - 1) * _CORROBORATION_PER_SOURCE,
        )
    score += _evidence_quality_bonus(best)
    if not confirmable:
        score = min(score * 0.40, 40.0)

    reason_parts = [
        f"source={best.source}",
        f"ownership={ownership:.0f} ({best.ownership_class.value})",
        f"independent_sources={independent}",
    ]
    if confirmable:
        reason_parts.append("confirmable")
    else:
        reason_parts.append("weak/reference")

    return VersionGroupScore(
        version=version,
        score=round(score, 2),
        ownership_confidence=ownership,
        independent_sources=independent,
        confirmable=confirmable,
        evidence_ids=tuple(sorted({item.evidence_id for item in items if item.evidence_id})),
        source_keys=source_keys,
        best_candidate=best,
        reason="; ".join(reason_parts),
    )


def _evidence_quality_bonus(candidate: VersionCandidate) -> float:
    source = candidate.source.lower()
    if source in {"package", "package_metadata", "manifest"}:
        return 5.0
    if source in {"runtime", "build_metadata"}:
        return 4.0
    if source in {"banner", "metadata", "sourcemap", "source_map"}:
        return 3.0
    if candidate.ownership_class == VersionOwnershipClass.ASSOCIATED:
        return 1.0
    return 0.0


def _retain_as_alternate(group: VersionGroupScore) -> bool:
    if group.confirmable:
        return True
    ownership = group.best_candidate.ownership_class
    return ownership in {
        VersionOwnershipClass.OWNED,
        VersionOwnershipClass.ASSOCIATED,
    }


def _final_confidence(group: VersionGroupScore) -> float:
    base = min(95.0, group.best_candidate.priority * 0.85)
    base += min(_MAX_CORROBORATION, max(0, group.independent_sources - 1) * 5.0)
    base = max(base, group.ownership_confidence * 0.7)
    return round(min(100.0, max(0.0, base)), 1)


def _primary_reason(
    top: VersionGroupScore,
    conflict: VersionConflictClass,
    alternates: tuple[str, ...],
) -> str:
    parts = [
        f"Primary {top.version} selected via {top.reason}",
        f"score={top.score:.1f}",
    ]
    if top.independent_sources > 1:
        parts.append(
            f"corroborated by {top.independent_sources} independent sources",
        )
    if conflict == VersionConflictClass.WEAK_ALTERNATE and alternates:
        parts.append(f"retained alternate(s): {', '.join(alternates)}")
    elif conflict == VersionConflictClass.NO_CONFLICT:
        parts.append("no meaningful conflict")
    return "; ".join(parts)


def _merge_evidence_ids(groups: list[VersionGroupScore]) -> tuple[str, ...]:
    ids: set[str] = set()
    for group in groups:
        ids.update(group.evidence_ids)
    return tuple(sorted(ids))
