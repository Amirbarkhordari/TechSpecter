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
        NegativeEvidence.RUNTIME_REFERENCE,
        NegativeEvidence.HTML_ATTRIBUTE,
        NegativeEvidence.SELF_REFERENCE,
        NegativeEvidence.GENERATED_TEMPLATE,
        NegativeEvidence.EXAMPLE_VALUE,
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

        # Structured / provider positives survive weak generic heuristics.
        has_structured = bool(
            {
                PositiveEvidence.PROVIDER_SPECIFIC_FORMAT,
                PositiveEvidence.STRUCTURED_SECRET,
                PositiveEvidence.CREDENTIAL_PAIR,
            }
            & set(candidate.positive_evidence)
        )

        hard_negatives = set(candidate.negative_evidence) & _REJECT_SIGNALS
        if hard_negatives and not has_structured:
            candidate.validation_state = ValidationState.REJECTED
            candidate.rejection_reason = sorted(hard_negatives)[0].value
            return candidate

        structured_blockers = {
            NegativeEvidence.EMPTY_VALUE,
            NegativeEvidence.FORM_REFERENCE,
            NegativeEvidence.HTML_ATTRIBUTE,
            NegativeEvidence.SELF_REFERENCE,
            NegativeEvidence.GENERATED_TEMPLATE,
        }
        if hard_negatives & structured_blockers:
            # Structured secrets still reject empty/form/template shells.
            candidate.validation_state = ValidationState.REJECTED
            candidate.rejection_reason = sorted(hard_negatives & structured_blockers)[0].value
            return candidate

        if candidate.validation_state == ValidationState.PENDING:
            if has_structured or PositiveEvidence.REALISTIC_SECRET_SHAPE in set(
                candidate.positive_evidence,
            ):
                candidate.validation_state = ValidationState.CONFIRMED
            else:
                candidate.validation_state = ValidationState.CANDIDATE_ONLY
                candidate.rejection_reason = candidate.rejection_reason or "pending_unresolved"

        return candidate
