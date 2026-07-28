"""Scoring and confidence engines."""

from __future__ import annotations

from dataclasses import dataclass, field

from techspecter.fingerprinting.detection.correlation import correlate_evaluation, correlation_bonus
from techspecter.fingerprinting.detection.models import ScoringBreakdown, TechnologyEvaluation
from techspecter.fingerprinting.detection.weights import ScoringWeights


@dataclass(slots=True)
class ScoringEngine:
    """Reusable weighted scoring subsystem."""

    weights: ScoringWeights = field(default_factory=ScoringWeights)

    def score(self, evaluation: TechnologyEvaluation) -> ScoringBreakdown:
        """Calculate explainable score components for an evaluation."""
        if evaluation.rejected or not evaluation.matched_rules:
            return ScoringBreakdown(final_confidence=0.0)

        evidence_score = sum(match.weight for match in evaluation.matched_rules)
        context = correlate_evaluation(evaluation, weights=self.weights)
        corr_bonus = correlation_bonus(context, weights=self.weights)
        priority_bonus = min(10.0, evaluation.signature.priority / 10.0)
        penalty = evaluation.penalty

        final = min(100.0, max(0.0, evidence_score + corr_bonus + priority_bonus - penalty))
        final = min(100.0, max(0.0, final + evaluation.signature.confidence_modifier))

        components = {
            "evidence_score": round(evidence_score, 2),
            "correlation_bonus": round(corr_bonus, 2),
            "priority_bonus": round(priority_bonus, 2),
            "penalty": round(penalty, 2),
        }
        return ScoringBreakdown(
            evidence_score=evidence_score,
            correlation_bonus=corr_bonus,
            priority_bonus=priority_bonus,
            penalty=penalty,
            final_confidence=round(final, 2),
            components=components,
        )

    def _max_possible_score(self, evaluation: TechnologyEvaluation) -> float:
        """Estimate maximum achievable score for normalization."""
        _ = evaluation
        return 100.0


@dataclass(slots=True)
class ConfidenceEngine:
    """Calculate final detection confidence from scoring breakdown."""

    weights: ScoringWeights = field(default_factory=ScoringWeights)
    scorer: ScoringEngine | None = None

    def __post_init__(self) -> None:
        """Initialize nested scorer."""
        if self.scorer is None:
            self.scorer = ScoringEngine(weights=self.weights)

    def calculate(self, evaluation: TechnologyEvaluation) -> ScoringBreakdown:
        """Return explainable confidence breakdown."""
        scorer = self.scorer or ScoringEngine(weights=self.weights)
        breakdown = scorer.score(evaluation)
        if breakdown.final_confidence < self.weights.min_detection_confidence:
            return ScoringBreakdown(
                evidence_score=breakdown.evidence_score,
                correlation_bonus=breakdown.correlation_bonus,
                priority_bonus=breakdown.priority_bonus,
                penalty=breakdown.penalty,
                final_confidence=0.0,
                components={**breakdown.components, "filtered": 1.0},
            )
        return breakdown

    def passes_threshold(self, confidence: float) -> bool:
        """Return whether confidence meets minimum detection threshold."""
        return confidence >= self.weights.min_detection_confidence
