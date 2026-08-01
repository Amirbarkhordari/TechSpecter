"""Technology detection merging and duplicate suppression."""

from __future__ import annotations

from dataclasses import dataclass

from techspecter.fingerprinting.detection.models import (
    ScoringBreakdown,
    TechnologyEvaluation,
    VersionResolution,
    technology_match_from_evaluation,
)
from techspecter.fingerprinting.models import PatternEvidence, TechnologyMatch


@dataclass(slots=True)
class TechnologyMerger:
    """Merge duplicate technology detections into a single explainable match."""

    def merge_matches(self, matches: list[TechnologyMatch]) -> list[TechnologyMatch]:
        """Merge matches sharing the same technology ID."""
        grouped: dict[str, list[TechnologyMatch]] = {}
        for match in matches:
            grouped.setdefault(match.technology.id, []).append(match)

        merged: list[TechnologyMatch] = []
        for _tech_id, items in grouped.items():
            if len(items) == 1:
                merged.append(items[0])
                continue
            merged.append(self._merge_group(items))
        return sorted(merged, key=lambda item: (-item.confidence, item.technology.name.lower()))

    def merge_evaluations(
        self,
        evaluations: list[TechnologyEvaluation],
    ) -> dict[str, TechnologyEvaluation]:
        """Merge evaluations for the same technology signature."""
        grouped: dict[str, list[TechnologyEvaluation]] = {}
        for evaluation in evaluations:
            if evaluation.rejected:
                continue
            grouped.setdefault(evaluation.signature.id, []).append(evaluation)

        merged: dict[str, TechnologyEvaluation] = {}
        for tech_id, items in grouped.items():
            if len(items) == 1:
                merged[tech_id] = items[0]
                continue
            merged[tech_id] = self._merge_evaluations(items)
        return merged

    def build_merged_matches(
        self,
        evaluations: dict[str, TechnologyEvaluation],
        scoring: dict[str, ScoringBreakdown],
        versions: dict[str, VersionResolution],
    ) -> list[TechnologyMatch]:
        """Build one technology match per detected technology."""
        matches: list[TechnologyMatch] = []
        for tech_id, evaluation in evaluations.items():
            breakdown = scoring.get(tech_id)
            version = versions.get(tech_id)
            if breakdown is None or version is None:
                continue
            if breakdown.final_confidence <= 0:
                continue
            matches.append(
                technology_match_from_evaluation(
                    evaluation,
                    version=version,
                    confidence=breakdown.final_confidence,
                    breakdown=breakdown,
                ),
            )
        return self.merge_matches(matches)

    def _merge_group(self, matches: list[TechnologyMatch]) -> TechnologyMatch:
        """Merge multiple matches for one technology."""
        primary = max(matches, key=lambda item: item.confidence)
        patterns: set[str] = set()
        evidence_items: list[PatternEvidence] = []
        seen_evidence: set[tuple[str, str]] = set()
        evidence_ids: set[str] = set()
        resources: set[str] = set()
        rejected: set[str] = set()
        sources: set[str] = set()
        reasons: set[str] = set()
        breakdown: dict[str, float] = dict(primary.confidence_breakdown)

        for match in matches:
            patterns.update(match.matched_patterns)
            evidence_ids.update(match.supporting_evidence_ids)
            resources.update(match.matched_resources)
            if match.filename:
                resources.add(match.filename)
            if match.source_url:
                resources.add(match.source_url)
            rejected.update(match.rejected_version_candidates)
            if match.version_source:
                sources.add(match.version_source)
            if match.detection_reason:
                reasons.add(match.detection_reason)
            for item in match.evidence:
                key = (item.matcher, item.pattern)
                if key in seen_evidence:
                    continue
                seen_evidence.add(key)
                evidence_items.append(item)
            for key, value in match.confidence_breakdown.items():
                breakdown[key] = max(breakdown.get(key, 0.0), value)

        confidence = min(
            100.0,
            primary.confidence + min(10.0, (len(matches) - 1) * 2.0),
        )
        return primary.model_copy(
            update={
                "confidence": round(confidence, 1),
                "matched_patterns": sorted(patterns),
                "evidence": evidence_items,
                "supporting_evidence_ids": sorted(evidence_ids),
                "evidence_count": len(evidence_items) or len(evidence_ids),
                "matched_resources": sorted(resources),
                "rejected_version_candidates": sorted(rejected),
                "evidence_sources": sorted(sources),
                "confidence_breakdown": breakdown,
                "detection_reason": (
                    "; ".join(sorted(reasons)) if reasons else primary.detection_reason
                ),
            },
        )

    def _merge_evaluations(
        self,
        evaluations: list[TechnologyEvaluation],
    ) -> TechnologyEvaluation:
        """Merge multiple evaluations for one technology signature."""
        primary = max(evaluations, key=lambda item: len(item.matched_rules))
        matched = tuple(
            {
                match.rule.id: match
                for evaluation in evaluations
                for match in evaluation.matched_rules
            }.values(),
        )
        negative = tuple(
            {
                match.rule.id: match
                for evaluation in evaluations
                for match in evaluation.negative_matches
            }.values(),
        )
        required = tuple(
            {
                match.rule.id: match
                for evaluation in evaluations
                for match in evaluation.required_matches
            }.values(),
        )
        penalty = max(evaluation.penalty for evaluation in evaluations)
        return TechnologyEvaluation(
            signature=primary.signature,
            matched_rules=matched,
            negative_matches=negative,
            required_matches=required,
            raw_score=sum(evaluation.raw_score for evaluation in evaluations),
            correlation_bonus=max(evaluation.correlation_bonus for evaluation in evaluations),
            penalty=penalty,
        )
