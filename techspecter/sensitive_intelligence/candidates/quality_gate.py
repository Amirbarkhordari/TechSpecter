"""Sensitive match quality gate."""

from __future__ import annotations

from dataclasses import dataclass

from techspecter.sensitive_intelligence.candidates.models import (
    NegativeEvidence,
    PositiveEvidence,
    SensitiveCandidate,
    ValidationState,
)

_REJECT_SIGNALS = frozenset(
    {
        NegativeEvidence.EMPTY_VALUE,
        NegativeEvidence.PLACEHOLDER_VALUE,
        NegativeEvidence.FORM_REFERENCE,
        NegativeEvidence.FORM_FIELD,
        NegativeEvidence.RUNTIME_REFERENCE,
        NegativeEvidence.HTML_ATTRIBUTE,
        NegativeEvidence.SELF_REFERENCE,
        NegativeEvidence.GENERATED_TEMPLATE,
        NegativeEvidence.EXAMPLE_VALUE,
    },
)

_STRUCTURED_POSITIVES = frozenset(
    {
        PositiveEvidence.PROVIDER_SPECIFIC_FORMAT,
        PositiveEvidence.STRUCTURED_SECRET,
        PositiveEvidence.CREDENTIAL_PAIR,
    },
)

_STRUCTURED_BLOCKERS = frozenset(
    {
        NegativeEvidence.EMPTY_VALUE,
        NegativeEvidence.FORM_REFERENCE,
        NegativeEvidence.FORM_FIELD,
        NegativeEvidence.HTML_ATTRIBUTE,
        NegativeEvidence.SELF_REFERENCE,
        NegativeEvidence.GENERATED_TEMPLATE,
    },
)


@dataclass(slots=True)
class SensitiveMatchQualityGate:
    """Final gate before confirmed findings enter FindingTracker."""

    def evaluate(self, candidate: SensitiveCandidate) -> SensitiveCandidate:
        """Enforce confirmation/rejection decisions for a candidate."""
        if candidate.validation_state == ValidationState.REJECTED:
            return candidate

        if candidate.validation_state == ValidationState.CANDIDATE_ONLY:
            return candidate

        positives = set(candidate.positive_evidence)
        has_structured = bool(positives & _STRUCTURED_POSITIVES)
        hard_negatives = set(candidate.negative_evidence) & _REJECT_SIGNALS

        if hard_negatives and not has_structured:
            candidate.validation_state = ValidationState.REJECTED
            candidate.rejection_reason = sorted(hard_negatives)[0].value
            return candidate

        if hard_negatives & _STRUCTURED_BLOCKERS:
            candidate.validation_state = ValidationState.REJECTED
            candidate.rejection_reason = sorted(hard_negatives & _STRUCTURED_BLOCKERS)[0].value
            return candidate

        if candidate.validation_state == ValidationState.PENDING:
            if has_structured or PositiveEvidence.REALISTIC_SECRET_SHAPE in positives:
                candidate.validation_state = ValidationState.CONFIRMED
            else:
                candidate.validation_state = ValidationState.CANDIDATE_ONLY
                candidate.rejection_reason = candidate.rejection_reason or "pending_unresolved"

        return candidate
