"""Scoring and confidence engines."""

from __future__ import annotations

from dataclasses import dataclass, field

from techspecter.fingerprinting.detection.correlation import correlate_evaluation, correlation_bonus
from techspecter.fingerprinting.detection.models import (
    ScoringBreakdown,
    TechnologyEvaluation,
    VersionResolution,
)
from techspecter.fingerprinting.detection.weights import ScoringWeights
from techspecter.fingerprinting.models import UNKNOWN_VERSION

_MAX_EVIDENCE_CONTRIBUTION = 75.0


@dataclass(slots=True)
class ScoringEngine:
    """Reusable weighted scoring subsystem."""

    weights: ScoringWeights = field(default_factory=ScoringWeights)

    def score(self, evaluation: TechnologyEvaluation) -> ScoringBreakdown:
        """Calculate explainable score components for an evaluation."""
        if evaluation.rejected or not evaluation.matched_rules:
            return ScoringBreakdown(final_confidence=0.0)

        raw_evidence = sum(match.weight for match in evaluation.matched_rules)
        evidence_score = min(_MAX_EVIDENCE_CONTRIBUTION, raw_evidence)
        context = correlate_evaluation(evaluation, weights=self.weights)
        corr_bonus = correlation_bonus(context, weights=self.weights)
        priority_bonus = min(10.0, evaluation.signature.priority / 10.0)
        penalty = evaluation.penalty

        final = min(100.0, max(0.0, evidence_score + corr_bonus + priority_bonus - penalty))
        final = min(100.0, max(0.0, final + evaluation.signature.confidence_modifier))

        components = {
            "evidence_score": round(evidence_score, 1),
            "correlation_bonus": round(corr_bonus, 1),
            "priority_bonus": round(priority_bonus, 1),
            "penalty": round(penalty, 1),
        }
        return ScoringBreakdown(
            evidence_score=evidence_score,
            correlation_bonus=corr_bonus,
            priority_bonus=priority_bonus,
            penalty=penalty,
            final_confidence=round(final, 1),
            components=components,
        )


@dataclass(slots=True)
class ConfidenceEngine:
    """Calculate final detection confidence from scoring breakdown."""

    weights: ScoringWeights = field(default_factory=ScoringWeights)
    scorer: ScoringEngine | None = None

    def __post_init__(self) -> None:
        """Initialize nested scorer."""
        if self.scorer is None:
            self.scorer = ScoringEngine(weights=self.weights)

    def calculate(
        self,
        evaluation: TechnologyEvaluation,
        *,
        version: VersionResolution | None = None,
    ) -> ScoringBreakdown:
        """Return explainable confidence breakdown."""
        scorer = self.scorer or ScoringEngine(weights=self.weights)
        breakdown = scorer.score(evaluation)
        calibrated = self.calibrate(breakdown, evaluation, version=version)
        if calibrated.final_confidence < self.weights.min_detection_confidence:
            return ScoringBreakdown(
                evidence_score=calibrated.evidence_score,
                correlation_bonus=calibrated.correlation_bonus,
                priority_bonus=calibrated.priority_bonus,
                penalty=calibrated.penalty,
                final_confidence=0.0,
                components={**calibrated.components, "filtered": 1.0},
            )
        return calibrated

    def calibrate(
        self,
        breakdown: ScoringBreakdown,
        evaluation: TechnologyEvaluation,
        *,
        version: VersionResolution | None = None,
    ) -> ScoringBreakdown:
        """Apply confidence calibration for stable, explainable percentages."""
        context = correlate_evaluation(evaluation, weights=self.weights)
        final = breakdown.final_confidence

        independent_sources = len(context.sources)
        if independent_sources >= 2:
            final += min(12.0, (independent_sources - 1) * 4.0)
        if len(context.resources) >= 2:
            final += min(8.0, (len(context.resources) - 1) * 2.0)

        if version is not None:
            if version.version != UNKNOWN_VERSION and version.confidence >= 60.0:
                final += min(6.0, version.confidence / 15.0)
            if version.rejected_candidates:
                final -= min(8.0, len(version.rejected_candidates) * 2.0)

        if evaluation.negative_matches:
            final -= min(15.0, len(evaluation.negative_matches) * 5.0)

        final = round(min(100.0, max(0.0, final)), 1)
        components = {
            **breakdown.components,
            "calibrated_confidence": final,
        }
        return ScoringBreakdown(
            evidence_score=breakdown.evidence_score,
            correlation_bonus=breakdown.correlation_bonus,
            priority_bonus=breakdown.priority_bonus,
            penalty=breakdown.penalty,
            final_confidence=final,
            components=components,
        )

    def passes_threshold(self, confidence: float) -> bool:
        """Return whether confidence meets minimum detection threshold."""
        return confidence >= self.weights.min_detection_confidence
