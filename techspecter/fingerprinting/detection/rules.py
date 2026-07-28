"""Rule evaluation engine."""

from __future__ import annotations

import logging

from techspecter.fingerprinting.detection.matchers import match_rule
from techspecter.fingerprinting.detection.models import (
    NormalizedEvidence,
    RuleMatch,
    TechnologyEvaluation,
)
from techspecter.fingerprinting.signatures.models import SignatureRule, TechnologySignature

logger = logging.getLogger(__name__)


class RuleEvaluator:
    """Evaluate technology signatures against normalized evidence."""

    def evaluate(
        self,
        signature: TechnologySignature,
        evidence: tuple[NormalizedEvidence, ...],
    ) -> TechnologyEvaluation:
        """Evaluate one signature against all evidence."""
        positive = _collect_matches(signature.positive_rules, evidence)
        optional = _collect_matches(signature.optional_rules, evidence)
        required = _collect_matches(signature.required_rules, evidence)
        negative = _collect_matches(signature.negative_rules, evidence)

        all_matches = _dedupe_matches(list(positive + optional + required))
        raw_score = sum(match.weight for match in all_matches)

        rejected = False
        rejection_reason: str | None = None

        if signature.required_rules and len(required) < len(signature.required_rules):
            rejected = True
            rejection_reason = "Required rules not satisfied"

        if negative and not required:
            rejected = True
            rejection_reason = "Negative evidence matched without required confirmation"

        if negative and required and raw_score < signature.minimum_score:
            rejected = True
            rejection_reason = "Negative evidence with insufficient supporting score"

        if raw_score < signature.minimum_score:
            rejected = True
            rejection_reason = rejection_reason or "Score below minimum threshold"

        return TechnologyEvaluation(
            signature=signature,
            matched_rules=all_matches,
            negative_matches=negative,
            required_matches=required,
            raw_score=raw_score,
            rejected=rejected,
            rejection_reason=rejection_reason,
        )


def _collect_matches(
    rules: tuple[SignatureRule, ...],
    evidence: tuple[NormalizedEvidence, ...],
) -> tuple[RuleMatch, ...]:
    """Collect rule matches across evidence items."""
    matches: list[RuleMatch] = []
    seen: set[tuple[str, str]] = set()
    for rule in rules:
        for item in evidence:
            result = match_rule(rule, item)
            if result is None:
                continue
            key = (rule.id, result.evidence.id)
            if key in seen:
                continue
            seen.add(key)
            matches.append(result)
    return tuple(matches)


def _dedupe_matches(matches: list[RuleMatch]) -> tuple[RuleMatch, ...]:
    """Remove duplicate rule/evidence pairs."""
    seen: set[tuple[str, str]] = set()
    deduped: list[RuleMatch] = []
    for match in matches:
        key = (match.rule.id, match.evidence.id)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(match)
    return tuple(deduped)
