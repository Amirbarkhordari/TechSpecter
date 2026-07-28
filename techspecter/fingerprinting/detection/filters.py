"""False positive reduction filters."""

from __future__ import annotations

from dataclasses import dataclass, field

from techspecter.fingerprinting.detection.models import TechnologyEvaluation
from techspecter.fingerprinting.detection.weights import ScoringWeights


@dataclass(slots=True)
class FalsePositiveReducer:
    """Apply precision-focused filters before confidence calculation."""

    weights: ScoringWeights = field(default_factory=ScoringWeights)

    def filter_evaluations(
        self,
        evaluations: list[TechnologyEvaluation],
    ) -> list[TechnologyEvaluation]:
        """Remove weak or rejected evaluations."""
        filtered: list[TechnologyEvaluation] = []
        for evaluation in evaluations:
            if evaluation.rejected:
                continue
            if evaluation.raw_score < evaluation.signature.minimum_score:
                continue
            if self._only_weak_evidence(evaluation):
                continue
            filtered.append(evaluation)
        return self._suppress_duplicates(filtered)

    def _only_weak_evidence(self, evaluation: TechnologyEvaluation) -> bool:
        """Return True when all matched evidence is below weak threshold."""
        if not evaluation.matched_rules:
            return True
        return all(
            match.weight < self.weights.weak_evidence_threshold
            for match in evaluation.matched_rules
        )

    def _suppress_duplicates(
        self,
        evaluations: list[TechnologyEvaluation],
    ) -> list[TechnologyEvaluation]:
        """Suppress duplicate technology IDs keeping highest raw score."""
        best: dict[str, TechnologyEvaluation] = {}
        for evaluation in evaluations:
            tech_id = evaluation.signature.id
            existing = best.get(tech_id)
            if existing is None or evaluation.raw_score > existing.raw_score:
                best[tech_id] = evaluation
        return list(best.values())
