"""Production-grade version resolution engine."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from techspecter.fingerprinting.detection.models import RuleMatch, VersionResolution
from techspecter.fingerprinting.detection.version.candidates import (
    VersionCandidate,
    VersionCandidateCollector,
    normalize_version,
)
from techspecter.fingerprinting.detection.version.priorities import priority_for_source
from techspecter.fingerprinting.detection.weights import ScoringWeights
from techspecter.fingerprinting.evidence.models import Evidence
from techspecter.fingerprinting.models import UNKNOWN_VERSION
from techspecter.fingerprinting.signatures.models import TechnologySignature


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
    ) -> VersionResolution:
        """Select the best supported version for a technology."""
        resources = frozenset(
            filter(
                None,
                (*(match.evidence.url or match.evidence.file for match in matched_rules),),
            ),
        )
        candidates = self.collector.collect(
            signature,
            evidence_items=evidence_items,
            matched_resources=resources,
        )
        if not candidates:
            return VersionResolution(
                version=UNKNOWN_VERSION,
                confidence=0.0,
                source="none",
                reason="No version candidates matched technology context",
            )

        ranked = self._rank_candidates(candidates)
        best = ranked[0]
        rejected = tuple(
            sorted({item.version for item in ranked[1:] if item.version != best.version}),
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
        )

    def _rank_candidates(self, candidates: tuple[VersionCandidate, ...]) -> list[VersionCandidate]:
        """Rank candidates by priority, agreement, and specificity."""
        version_counts = Counter(item.version for item in candidates)
        scored: list[tuple[float, VersionCandidate]] = []
        for candidate in candidates:
            score = candidate.priority
            score += min(15.0, (version_counts[candidate.version] - 1) * 5.0)
            if candidate.extractor_id:
                score += 2.0
            if candidate.resource:
                score += 1.0
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
        parts = [f"Highest-ranked candidate from {best.source} (priority {best.priority:.0f})"]
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
            )
            continue
        merged[tech_id] = resolution
    return merged
