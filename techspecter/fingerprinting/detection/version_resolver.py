"""Production-grade version resolution engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from techspecter.fingerprinting.detection.models import RuleMatch, VersionResolution
from techspecter.fingerprinting.detection.version.candidates import (
    VersionCandidateCollector,
    normalize_version,
)
from techspecter.fingerprinting.detection.weights import ScoringWeights
from techspecter.fingerprinting.evidence.models import Evidence
from techspecter.fingerprinting.models import UNKNOWN_VERSION
from techspecter.fingerprinting.signatures.models import TechnologySignature
from techspecter.versioning.models import VersionAttributionState
from techspecter.versioning.resolution import resolve_primary_version


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
        """Select the primary version for a technology when evidence allows."""
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
        outcome = resolve_primary_version(
            candidates,
            technology_confidence=technology_confidence,
        )
        # Prefer rejected list that also surfaces non-primary versions for
        # backward-compatible consumers that only read rejected_candidates.
        rejected = tuple(
            sorted(
                {
                    *outcome.rejected_versions,
                    *(
                        version
                        for version in outcome.alternate_versions
                        if outcome.primary_version != UNKNOWN_VERSION
                    ),
                },
            ),
        )
        return VersionResolution(
            version=outcome.primary_version,
            confidence=outcome.confidence,
            source=outcome.source,
            reason=outcome.reason,
            rejected_candidates=rejected,
            candidate_count=outcome.candidate_count or len(candidates),
            evidence_ids=outcome.evidence_ids,
            winning_candidate=outcome.winning_candidate,
            attribution_state=outcome.attribution_state.value,
            ownership_class=outcome.ownership_class,
            ownership_confidence=outcome.ownership_confidence,
            version_confidence=outcome.version_confidence,
            technology_confidence=technology_confidence,
            candidates=candidates,
            alternate_versions=outcome.alternate_versions,
            conflict_class=outcome.conflict_class.value,
            independent_source_count=outcome.independent_source_count,
        )


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
                alternate_versions=resolution.alternate_versions,
                conflict_class=resolution.conflict_class,
                independent_source_count=resolution.independent_source_count,
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
                alternate_versions=resolution.alternate_versions,
                conflict_class=resolution.conflict_class,
                independent_source_count=resolution.independent_source_count,
            )
            continue
        merged[tech_id] = resolution
    return merged
