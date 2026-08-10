"""Centralized confidence and severity calibration for sensitive candidates."""

from __future__ import annotations

from techspecter.sensitive_intelligence.candidates.models import (
    NegativeEvidence,
    PositiveEvidence,
    SensitiveCandidate,
    SensitiveCorrelation,
    ValidationState,
    ValueStrength,
)
from techspecter.sensitive_intelligence.candidates.policies import (
    DetectorPolicy,
    resolve_detector_policy,
)
from techspecter.sensitive_intelligence.models import SeverityLevel

_SEVERITY_RANK = {
    SeverityLevel.INFORMATIONAL: 1,
    SeverityLevel.LOW: 2,
    SeverityLevel.MEDIUM: 3,
    SeverityLevel.HIGH: 4,
    SeverityLevel.CRITICAL: 5,
}
_RANK_TO_SEVERITY = {rank: level for level, rank in _SEVERITY_RANK.items()}

_BLOCKING = frozenset(
    {
        NegativeEvidence.EMPTY_VALUE,
        NegativeEvidence.PLACEHOLDER_VALUE,
        NegativeEvidence.WEAK_GENERIC_VALUE,
        NegativeEvidence.RUNTIME_REFERENCE,
        NegativeEvidence.SELF_REFERENCE,
        NegativeEvidence.FORM_FIELD,
        NegativeEvidence.FORM_REFERENCE,
        NegativeEvidence.HTML_ATTRIBUTE,
        NegativeEvidence.GENERATED_TEMPLATE,
        NegativeEvidence.EXAMPLE_VALUE,
    },
)


def calibrate_candidate(
    candidate: SensitiveCandidate,
    *,
    correlations: list[SensitiveCorrelation] | None = None,
    policy: DetectorPolicy | None = None,
) -> SensitiveCandidate:
    """Adjust confidence/severity after validation and optional correlation."""
    policy = policy or resolve_detector_policy(candidate)
    correlations = correlations or []
    related = [
        item
        for item in correlations
        if candidate.candidate_id in item.candidate_ids
        or candidate.correlation_ids
        and item.correlation_id in candidate.correlation_ids
    ]

    confidence = candidate.adjusted_confidence or candidate.original_confidence
    confidence += policy.confidence_adjustment

    confirmed_related = [
        item for item in related if item.validation_state == ValidationState.CONFIRMED
    ]
    if confirmed_related:
        confidence += sum(item.confidence_contribution for item in confirmed_related)

    # Weak/negative candidates never escalate.
    if candidate.validation_state in {ValidationState.REJECTED, ValidationState.CANDIDATE_ONLY}:
        if set(candidate.negative_evidence) & _BLOCKING:
            confidence = min(confidence, 40.0)
        candidate.adjusted_confidence = max(0.0, min(100.0, confidence))
        candidate.adjusted_severity = _clamp_severity(
            candidate.original_severity,
            floor=None,
            ceiling=SeverityLevel.MEDIUM
            if candidate.validation_state == ValidationState.CANDIDATE_ONLY
            else SeverityLevel.LOW,
        )
        return candidate

    if candidate.value_strength in {ValueStrength.WEAK, ValueStrength.PLACEHOLDER, ValueStrength.EMPTY}:
        candidate.adjusted_confidence = min(confidence, 45.0)
        candidate.adjusted_severity = SeverityLevel.LOW
        return candidate

    severity = candidate.original_severity
    if PositiveEvidence.PROVIDER_SPECIFIC_FORMAT in candidate.positive_evidence:
        severity = _max_severity(severity, SeverityLevel.HIGH)
    if PositiveEvidence.STRUCTURED_SECRET in candidate.positive_evidence:
        severity = _max_severity(severity, candidate.original_severity)

    if confirmed_related and candidate.value_strength in {
        ValueStrength.REALISTIC,
        ValueStrength.STRUCTURED,
    }:
        # Strong pairs may keep/raise toward policy ceiling, never from weak bases.
        severity = _max_severity(severity, SeverityLevel.HIGH)
        if candidate.original_severity == SeverityLevel.CRITICAL or any(
            item.severity_hint == SeverityLevel.CRITICAL for item in confirmed_related
        ):
            severity = SeverityLevel.CRITICAL
    elif confirmed_related:
        # Correlation present but value not strong: no Critical escalation.
        severity = _min_severity(severity, SeverityLevel.MEDIUM)

    severity = _clamp_severity(severity, floor=policy.severity_floor, ceiling=policy.severity_ceiling)
    candidate.adjusted_confidence = max(0.0, min(100.0, confidence))
    candidate.adjusted_severity = severity
    return candidate


def _max_severity(left: SeverityLevel, right: SeverityLevel) -> SeverityLevel:
    return left if _SEVERITY_RANK[left] >= _SEVERITY_RANK[right] else right


def _min_severity(left: SeverityLevel, right: SeverityLevel) -> SeverityLevel:
    return left if _SEVERITY_RANK[left] <= _SEVERITY_RANK[right] else right


def _clamp_severity(
    severity: SeverityLevel,
    *,
    floor: SeverityLevel | None,
    ceiling: SeverityLevel | None,
) -> SeverityLevel:
    rank = _SEVERITY_RANK[severity]
    if floor is not None:
        rank = max(rank, _SEVERITY_RANK[floor])
    if ceiling is not None:
        rank = min(rank, _SEVERITY_RANK[ceiling])
    return _RANK_TO_SEVERITY[rank]
