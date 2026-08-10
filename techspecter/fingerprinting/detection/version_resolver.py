"""Production-grade version resolution engine."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from techspecter.fingerprinting.detection.models import RuleMatch, VersionResolution
from techspecter.fingerprinting.detection.version.candidates import (
    VersionCandidate,
    VersionCandidateCollector,
    candidate_supports_confirmation,
    normalize_version,
)
from techspecter.fingerprinting.detection.version.priorities import priority_for_source
from techspecter.fingerprinting.detection.weights import ScoringWeights
from techspecter.fingerprinting.evidence.models import Evidence
from techspecter.fingerprinting.models import UNKNOWN_VERSION
from techspecter.fingerprinting.signatures.models import TechnologySignature
from techspecter.versioning.models import VersionAttributionState
from techspecter.versioning.validator import is_valid_version


@dataclass(slots=True)
class VersionResolutionEngine:
    """Resolve version candidates collected during evidence analysis."""

    weights: ScoringWeights = field(default_factory=ScoringWeights)
    collector: VersionCandidateCollector = field(default_factory=VersionCandidateCollector)

    def resolve(
        self,
        signature: TechnologySignature,
        *,
        evidence_items: tuple[Evidence, ...],
        matched_rules: tuple[RuleMatch, ...],
        technology_confidence: float | None = None,
    ) -> VersionResolution:
        """Select the best supported version for a technology."""
        resources = frozenset(
            filter(
                None,
                (*(match.evidence.url or match.evidence.file for match in matched_rules),),
            ),
        )
        matched_evidence_ids = frozenset(match.evidence.id for match in matched_rules)
        candidates = self.collector.collect(
            signature,
            evidence_items=evidence_items,
            matched_evidence_ids=matched_evidence_ids,
            matched_resources=resources,
            technology_confidence=technology_confidence,
        )
        if not candidates:
            return VersionResolution(
                version=UNKNOWN_VERSION,
                confidence=0.0,
                source="none",
                reason="No version candidates matched technology context",
                attribution_state=VersionAttributionState.CANDIDATE.value,
                technology_confidence=technology_confidence,
            )

        ranked = self._rank_candidates(candidates)
        if not ranked:
            return VersionResolution(
                version=UNKNOWN_VERSION,
                confidence=0.0,
                source="none",
                reason="All version candidates were invalid or placeholder values",
                rejected_candidates=tuple(sorted({item.version for item in candidates})),
                candidate_count=len(candidates),
                attribution_state=VersionAttributionState.REJECTED.value,
                candidates=candidates,
                technology_confidence=technology_confidence,
            )

        confirmable = [item for item in ranked if candidate_supports_confirmation(item)]
        if not confirmable:
            best_weak = ranked[0]
            return VersionResolution(
                version=UNKNOWN_VERSION,
                confidence=0.0,
                source=best_weak.source,
                reason=(
                    "Version evidence retained as candidate-only; "
                    "ownership is insufficient for confirmation "
                    f"(class={best_weak.ownership_class.value}, "
                    f"ownership_confidence={best_weak.ownership_confidence:.0f})"
                ),
                rejected_candidates=tuple(
                    sorted({item.version for item in ranked if item.version != best_weak.version}),
                ),
                candidate_count=len(candidates),
                evidence_ids=tuple(
                    sorted({item.evidence_id for item in candidates if item.evidence_id}),
                ),
                attribution_state=VersionAttributionState.CANDIDATE.value,
                ownership_class=best_weak.ownership_class.value,
                ownership_confidence=best_weak.ownership_confidence,
                version_confidence=best_weak.version_confidence,
                technology_confidence=technology_confidence,
                candidates=candidates,
            )

        best = confirmable[0]
        rejected = tuple(
            sorted({item.version for item in ranked if item.version != best.version}),
        )
        agreement = self._agreement_score(ranked, best.version)
        confidence = self._version_confidence(best, agreement, rejected)

        return VersionResolution(
            version=best.version,
            confidence=round(confidence, 1),
            source=best.source,
            reason=self._selection_reason(best, agreement, rejected),
            rejected_candidates=rejected,
            candidate_count=len(candidates),
            evidence_ids=tuple(
                sorted({item.evidence_id for item in candidates if item.evidence_id}),
            ),
            winning_candidate=best.version,
            attribution_state=VersionAttributionState.CONFIRMED.value,
            ownership_class=best.ownership_class.value,
            ownership_confidence=best.ownership_confidence,
            version_confidence=round(confidence, 1),
            technology_confidence=technology_confidence,
            candidates=candidates,
        )

    def _rank_candidates(self, candidates: tuple[VersionCandidate, ...]) -> list[VersionCandidate]:
        """Rank candidates by priority, agreement, and specificity."""
        valid = [item for item in candidates if is_valid_version(item.version)]
        if not valid:
            return []
        version_counts = Counter(item.version for item in valid)
        scored: list[tuple[float, VersionCandidate]] = []
        for candidate in valid:
            score = candidate.priority
            score += min(15.0, (version_counts[candidate.version] - 1) * 5.0)
            if candidate.extractor_id:
                score += 2.0
            if candidate.resource:
                score += 1.0
            score += candidate.ownership_confidence * 0.05
            scored.append((score, candidate))
        scored.sort(key=lambda item: (-item[0], -priority_for_source(item[1].source)))
        return [item[1] for item in scored]

    def _agreement_score(
        self,
        ranked: list[VersionCandidate],
        winning_version: str,
    ) -> int:
        """Count independent sources agreeing on the winning version."""
        sources: set[str] = set()
        for candidate in ranked:
            if candidate.version == winning_version:
                sources.add(candidate.source)
        return len(sources)

    def _version_confidence(
        self,
        best: VersionCandidate,
        agreement: int,
        rejected: tuple[str, ...],
    ) -> float:
        """Calculate version-specific confidence."""
        base = min(95.0, best.priority * 0.85)
        base += min(15.0, (agreement - 1) * 5.0)
        if rejected:
            base -= min(20.0, len(rejected) * 4.0)
        return min(100.0, max(0.0, base))

    def _selection_reason(
        self,
        best: VersionCandidate,
        agreement: int,
        rejected: tuple[str, ...],
    ) -> str:
        """Build human-readable version selection reason."""
        parts = [
            f"Highest-ranked owned candidate from {best.source} "
            f"(priority {best.priority:.0f}, ownership {best.ownership_confidence:.0f})",
        ]
        if agreement > 1:
            parts.append(f"{agreement} independent sources agree")
        if rejected:
            parts.append(f"rejected {len(rejected)} conflicting candidate(s)")
        return "; ".join(parts)


def resolve_cross_file_versions(
    resolutions: dict[str, VersionResolution],
) -> dict[str, VersionResolution]:
    """Ensure version resolutions remain stable across merged detections."""
    merged: dict[str, VersionResolution] = {}
    for tech_id, resolution in resolutions.items():
        if resolution.version == UNKNOWN_VERSION:
            merged[tech_id] = resolution
            continue
        normalized = normalize_version(resolution.version)
        if normalized is None:
            merged[tech_id] = VersionResolution(
                version=UNKNOWN_VERSION,
                confidence=0.0,
                source="none",
                reason="Rejected invalid resolved version",
                rejected_candidates=(resolution.version, *resolution.rejected_candidates),
                candidate_count=resolution.candidate_count,
                evidence_ids=resolution.evidence_ids,
                attribution_state=VersionAttributionState.REJECTED.value,
                ownership_class=resolution.ownership_class,
                ownership_confidence=resolution.ownership_confidence,
                technology_confidence=resolution.technology_confidence,
                candidates=resolution.candidates,
            )
            continue
        if normalized != resolution.version:
            merged[tech_id] = VersionResolution(
                version=normalized,
                confidence=resolution.confidence,
                source=resolution.source,
                reason=resolution.reason,
                rejected_candidates=resolution.rejected_candidates,
                candidate_count=resolution.candidate_count,
                evidence_ids=resolution.evidence_ids,
                winning_candidate=normalized,
                attribution_state=resolution.attribution_state,
                ownership_class=resolution.ownership_class,
                ownership_confidence=resolution.ownership_confidence,
                version_confidence=resolution.version_confidence,
                technology_confidence=resolution.technology_confidence,
                candidates=resolution.candidates,
            )
            continue
        merged[tech_id] = resolution
    return merged
