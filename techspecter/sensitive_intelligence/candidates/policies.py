"""Detector-specific confirmation policies for sensitive candidates."""

from __future__ import annotations

from dataclasses import dataclass

from techspecter.sensitive_intelligence.candidates.models import (
    NegativeEvidence,
    SensitiveCandidate,
    ValueStrength,
)
from techspecter.sensitive_intelligence.models import FindingType, SeverityLevel

_DEFAULT_DISQUALIFIERS = frozenset(
    {
        NegativeEvidence.EMPTY_VALUE,
        NegativeEvidence.PLACEHOLDER_VALUE,
        NegativeEvidence.FORM_REFERENCE,
        NegativeEvidence.FORM_FIELD,
        NegativeEvidence.RUNTIME_REFERENCE,
        NegativeEvidence.HTML_ATTRIBUTE,
        NegativeEvidence.SELF_REFERENCE,
        NegativeEvidence.GENERATED_TEMPLATE,
    },
)


@dataclass(frozen=True, slots=True)
class DetectorPolicy:
    """Declarative confirmation requirements for a detector/category family."""

    policy_id: str
    minimum_value_strength: ValueStrength | None = ValueStrength.REALISTIC
    require_provider_format: bool = False
    allow_candidate_only: bool = True
    correlation_required: bool = False
    confidence_adjustment: float = 0.0
    severity_floor: SeverityLevel | None = None
    severity_ceiling: SeverityLevel | None = None
    disqualifying_negatives: frozenset[NegativeEvidence] = _DEFAULT_DISQUALIFIERS


_GENERIC_PASSWORD = DetectorPolicy(
    policy_id="generic-password",
    minimum_value_strength=ValueStrength.REALISTIC,
    confidence_adjustment=0.0,
    severity_ceiling=SeverityLevel.CRITICAL,
)
_GENERIC_TOKEN = DetectorPolicy(
    policy_id="generic-token",
    minimum_value_strength=ValueStrength.REALISTIC,
    confidence_adjustment=0.0,
    severity_ceiling=SeverityLevel.HIGH,
)
_PROVIDER_STRUCTURED = DetectorPolicy(
    policy_id="provider-structured",
    minimum_value_strength=None,
    require_provider_format=True,
    allow_candidate_only=False,
    confidence_adjustment=3.0,
)
_INTERNAL_CONFIG = DetectorPolicy(
    policy_id="internal-config",
    minimum_value_strength=None,
    allow_candidate_only=False,
    confidence_adjustment=0.0,
    severity_ceiling=SeverityLevel.MEDIUM,
    disqualifying_negatives=frozenset(
        {
            NegativeEvidence.EMPTY_VALUE,
            NegativeEvidence.RUNTIME_REFERENCE,
            NegativeEvidence.GENERATED_TEMPLATE,
        },
    ),
)
_CONTACT = DetectorPolicy(
    policy_id="contact-only",
    minimum_value_strength=None,
    allow_candidate_only=True,
    correlation_required=False,
    severity_ceiling=SeverityLevel.INFORMATIONAL,
)
_DEVELOPER = DetectorPolicy(
    policy_id="developer-artifact",
    minimum_value_strength=None,
    allow_candidate_only=False,
    severity_ceiling=SeverityLevel.MEDIUM,
    disqualifying_negatives=frozenset(),
)
_CORRELATED = DetectorPolicy(
    policy_id="correlated-pair",
    minimum_value_strength=ValueStrength.REALISTIC,
    allow_candidate_only=False,
    confidence_adjustment=4.0,
    severity_ceiling=SeverityLevel.CRITICAL,
)
_DEFAULT = DetectorPolicy(policy_id="default")


_RULE_POLICIES: dict[str, DetectorPolicy] = {
    "password-field": _GENERIC_PASSWORD,
    "username-field": DetectorPolicy(
        policy_id="username-field",
        minimum_value_strength=None,
        allow_candidate_only=True,
        severity_ceiling=SeverityLevel.MEDIUM,
    ),
    "client-id-field": DetectorPolicy(
        policy_id="client-id-field",
        minimum_value_strength=None,
        allow_candidate_only=True,
        severity_ceiling=SeverityLevel.LOW,
    ),
    "client-secret-field": _GENERIC_PASSWORD,
    "generic-api-key": _GENERIC_TOKEN,
    "session-token": _GENERIC_TOKEN,
    "bearer-token": _GENERIC_TOKEN,
    "high-entropy-secret": _GENERIC_TOKEN,
    "base64-secret": _GENERIC_TOKEN,
    "connection-string": _GENERIC_TOKEN,
    "correlated-credentials": _CORRELATED,
    "correlated-client-credentials": _CORRELATED,
    "correlated-aws-credentials": _CORRELATED,
    "correlated-token-authorization": _CORRELATED,
    "correlated-database-credentials": _CORRELATED,
    "jwt-token": _PROVIDER_STRUCTURED,
    "private-key": _PROVIDER_STRUCTURED,
    "ssh-private-key": _PROVIDER_STRUCTURED,
    "certificate": _PROVIDER_STRUCTURED,
    "aws-access-key": _PROVIDER_STRUCTURED,
    "aws-secret-key": _PROVIDER_STRUCTURED,
    "github-token": _PROVIDER_STRUCTURED,
    "gitlab-token": _PROVIDER_STRUCTURED,
    "google-api-key": _PROVIDER_STRUCTURED,
    "stripe-secret-key": _PROVIDER_STRUCTURED,
    "mongodb-uri": _PROVIDER_STRUCTURED,
    "postgresql-uri": _PROVIDER_STRUCTURED,
    "mysql-uri": _PROVIDER_STRUCTURED,
    "redis-uri": _PROVIDER_STRUCTURED,
    "internal-ip": _INTERNAL_CONFIG,
    "internal-hostname": _INTERNAL_CONFIG,
    "db-host-field": _INTERNAL_CONFIG,
    "db-user-field": DetectorPolicy(
        policy_id="db-user-field",
        minimum_value_strength=None,
        allow_candidate_only=True,
        severity_ceiling=SeverityLevel.MEDIUM,
    ),
}


def resolve_detector_policy(candidate: SensitiveCandidate) -> DetectorPolicy:
    """Return the detector policy for a candidate."""
    rule_id = candidate.rule_id or candidate.subtype
    if rule_id in _RULE_POLICIES:
        return _RULE_POLICIES[rule_id]
    if candidate.finding_type in {
        FindingType.EMAIL,
        FindingType.PHONE,
        FindingType.URL,
        FindingType.DOMAIN,
        FindingType.HOSTNAME,
        FindingType.UUID,
        FindingType.USERNAME,
    }:
        return _CONTACT
    if candidate.finding_type == FindingType.COMMENT:
        return _DEVELOPER
    if candidate.finding_type == FindingType.SENSITIVE_CONFIG:
        return _INTERNAL_CONFIG
    if candidate.finding_type in {FindingType.SECRET, FindingType.CREDENTIAL}:
        return _GENERIC_TOKEN
    return _DEFAULT


def policy_blocks_confirmation(candidate: SensitiveCandidate, policy: DetectorPolicy) -> str | None:
    """Return a rejection reason when policy disqualifiers are present."""
    negatives = set(candidate.negative_evidence)
    blocking = negatives & policy.disqualifying_negatives
    if not blocking:
        return None
    # Provider-structured policies still reject empty/form shells.
    if policy.require_provider_format:
        hard = blocking & {
            NegativeEvidence.EMPTY_VALUE,
            NegativeEvidence.FORM_REFERENCE,
            NegativeEvidence.FORM_FIELD,
            NegativeEvidence.HTML_ATTRIBUTE,
            NegativeEvidence.SELF_REFERENCE,
            NegativeEvidence.GENERATED_TEMPLATE,
        }
        if hard:
            return sorted(hard)[0].value
        return None
    return sorted(blocking)[0].value
