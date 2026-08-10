"""Sensitive candidate validation and confirmation boundary."""

from __future__ import annotations

from dataclasses import dataclass, field

from techspecter.sensitive_intelligence.candidates.builder import build_candidate, pair_values
from techspecter.sensitive_intelligence.candidates.context import ContextAnalyzer
from techspecter.sensitive_intelligence.candidates.models import (
    NegativeEvidence,
    PositiveEvidence,
    SensitiveCandidate,
    ValidationState,
    ValueStrength,
)
from techspecter.sensitive_intelligence.candidates.quality_gate import SensitiveMatchQualityGate
from techspecter.sensitive_intelligence.candidates.value import ValueAnalyzer, is_strong_secret_value
from techspecter.sensitive_intelligence.detectors.base import DetectorMatch
from techspecter.sensitive_intelligence.models import FindingCategory, FindingType
from techspecter.sensitive_intelligence.sources import TextAssetSource

# Precedence: these negatives generally block confirmation for generic keyword rules.
_HARD_REJECT = frozenset(
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

_CONTACT_TYPES = frozenset(
    {
        FindingType.EMAIL,
        FindingType.PHONE,
        FindingType.URL,
        FindingType.DOMAIN,
        FindingType.HOSTNAME,
        FindingType.UUID,
        FindingType.USERNAME,
    },
)

_STRUCTURED_RULES = frozenset(
    {
        "aws-access-key",
        "aws-secret-key",
        "google-api-key",
        "firebase-api-key",
        "stripe-secret-key",
        "github-token",
        "gitlab-token",
        "azure-key",
        "twilio-key",
        "slack-token",
        "discord-token",
        "openai-key",
        "anthropic-key",
        "jwt-token",
        "private-key",
        "ssh-private-key",
        "certificate",
        "gcp-service-account",
        "mongodb-uri",
        "postgresql-uri",
        "mysql-uri",
        "redis-uri",
        "ldap-credentials",
        "smtp-credentials",
        "basic-auth-token",
    },
)

_ASSIGNMENT_RULES = frozenset(
    {
        "password-field",
        "username-field",
        "generic-api-key",
        "session-token",
        "bearer-token",
        "connection-string",
        "high-entropy-secret",
        "base64-secret",
        "correlated-credentials",
    },
)

_STRUCTURED_POSITIVES = frozenset(
    {
        PositiveEvidence.PROVIDER_SPECIFIC_FORMAT,
        PositiveEvidence.STRUCTURED_SECRET,
    },
)


@dataclass(slots=True)
class SensitiveCandidateValidator:
    """Mandatory confirmation boundary between DetectorMatch and findings."""

    context_analyzer: ContextAnalyzer = field(default_factory=ContextAnalyzer)
    value_analyzer: ValueAnalyzer = field(default_factory=ValueAnalyzer)
    quality_gate: SensitiveMatchQualityGate = field(default_factory=SensitiveMatchQualityGate)

    def validate_match(
        self,
        match: DetectorMatch,
        *,
        detector_id: str,
        source: TextAssetSource,
    ) -> SensitiveCandidate:
        """Build, analyze, and gate a single detector match."""
        candidate = build_candidate(match, detector_id=detector_id, source=source)
        return self.validate(candidate)

    def validate(self, candidate: SensitiveCandidate) -> SensitiveCandidate:
        """Run context/value analysis and apply the quality gate."""
        self.context_analyzer.analyze(candidate)
        self.value_analyzer.analyze(candidate)
        self._apply_policy(candidate)
        return self.quality_gate.evaluate(candidate)

    def _apply_policy(self, candidate: SensitiveCandidate) -> None:
        """Adjust confidence and provisional state before the quality gate."""
        negatives = set(candidate.negative_evidence)
        positives = set(candidate.positive_evidence)
        confidence = candidate.original_confidence

        confidence -= 25.0 * len(negatives & _HARD_REJECT)
        confidence -= 10.0 * len(negatives - _HARD_REJECT)
        confidence += 5.0 * len(positives)
        candidate.adjusted_confidence = max(0.0, min(100.0, confidence))

        if candidate.finding_type in _CONTACT_TYPES:
            _add_negative(candidate, NegativeEvidence.CONTACT_ONLY)
            candidate.validation_state = ValidationState.CANDIDATE_ONLY
            candidate.rejection_reason = "contact_information_not_auto_confirmed"
            return

        if candidate.finding_type == FindingType.IP and candidate.subtype in {"ipv4", "ipv6"}:
            candidate.validation_state = ValidationState.CANDIDATE_ONLY
            candidate.rejection_reason = "generic_ip_requires_sensitive_config_rule"
            return

        if negatives & {
            NegativeEvidence.EMPTY_VALUE,
            NegativeEvidence.HTML_ATTRIBUTE,
            NegativeEvidence.SELF_REFERENCE,
            NegativeEvidence.FORM_FIELD,
        }:
            candidate.validation_state = ValidationState.REJECTED
            candidate.rejection_reason = sorted(negatives & _HARD_REJECT)[0].value
            return

        rule_id = candidate.rule_id or candidate.subtype

        if rule_id == "correlated-credentials":
            self._policy_correlated(candidate)
            return

        has_structured = bool(positives & _STRUCTURED_POSITIVES) or rule_id in _STRUCTURED_RULES
        if has_structured:
            self._policy_structured(candidate)
            return

        if rule_id in _ASSIGNMENT_RULES or candidate.category in {
            FindingCategory.CREDENTIALS,
            FindingCategory.SECRETS,
        }:
            self._policy_assignment(candidate)
            return

        # Sensitive configuration and developer artifacts: confirm unless hard negatives.
        if negatives & _HARD_REJECT:
            candidate.validation_state = ValidationState.REJECTED
            candidate.rejection_reason = "negative_evidence"
            return

        candidate.validation_state = ValidationState.CONFIRMED

    def _policy_structured(self, candidate: SensitiveCandidate) -> None:
        negatives = set(candidate.negative_evidence)
        positives = set(candidate.positive_evidence)
        blocking = {
            NegativeEvidence.EMPTY_VALUE,
            NegativeEvidence.FORM_REFERENCE,
            NegativeEvidence.FORM_FIELD,
            NegativeEvidence.HTML_ATTRIBUTE,
            NegativeEvidence.SELF_REFERENCE,
            NegativeEvidence.GENERATED_TEMPLATE,
        }
        # Provider/JWT/PEM formats remain authoritative over soft doc/test noise.
        if negatives & blocking and not (positives & _STRUCTURED_POSITIVES):
            candidate.validation_state = ValidationState.REJECTED
            candidate.rejection_reason = "structured_secret_negative_context"
            return
        if negatives & blocking and positives & _STRUCTURED_POSITIVES:
            # Empty/form/self shells still win even for structured rules.
            if negatives & {
                NegativeEvidence.EMPTY_VALUE,
                NegativeEvidence.FORM_REFERENCE,
                NegativeEvidence.FORM_FIELD,
                NegativeEvidence.HTML_ATTRIBUTE,
                NegativeEvidence.SELF_REFERENCE,
                NegativeEvidence.GENERATED_TEMPLATE,
            }:
                candidate.validation_state = ValidationState.REJECTED
                candidate.rejection_reason = "structured_secret_negative_context"
                return
        candidate.validation_state = ValidationState.CONFIRMED

    def _policy_assignment(self, candidate: SensitiveCandidate) -> None:
        negatives = set(candidate.negative_evidence)
        positives = set(candidate.positive_evidence)

        if negatives & _HARD_REJECT:
            # Hard negatives win for generic keyword assignments unless a true provider format.
            if positives & _STRUCTURED_POSITIVES and not (
                negatives
                & {
                    NegativeEvidence.EMPTY_VALUE,
                    NegativeEvidence.FORM_REFERENCE,
                    NegativeEvidence.FORM_FIELD,
                    NegativeEvidence.SELF_REFERENCE,
                    NegativeEvidence.GENERATED_TEMPLATE,
                    NegativeEvidence.HTML_ATTRIBUTE,
                }
            ):
                candidate.validation_state = ValidationState.CONFIRMED
                return
            candidate.validation_state = ValidationState.REJECTED
            candidate.rejection_reason = sorted(negatives & _HARD_REJECT)[0].value
            return

        if NegativeEvidence.WEAK_GENERIC_VALUE in negatives and not (
            positives & {PositiveEvidence.HIGH_ENTROPY, PositiveEvidence.PROVIDER_SPECIFIC_FORMAT}
        ):
            candidate.validation_state = ValidationState.REJECTED
            candidate.rejection_reason = "weak_generic_value"
            return

        if NegativeEvidence.EXAMPLE_VALUE in negatives and PositiveEvidence.PROVIDER_SPECIFIC_FORMAT not in positives:
            candidate.validation_state = ValidationState.REJECTED
            candidate.rejection_reason = "example_value"
            return

        if NegativeEvidence.TEST_FIXTURE in negatives:
            # Weak/placeholder fixtures are rejected above; realistic secrets in fixtures remain.
            if candidate.value_strength in {
                ValueStrength.PLACEHOLDER,
                ValueStrength.WEAK,
                ValueStrength.EMPTY,
            }:
                candidate.validation_state = ValidationState.REJECTED
                candidate.rejection_reason = "test_fixture_weak_value"
                return

        if NegativeEvidence.DOCUMENTATION_CONTEXT in negatives:
            # Documentation with a realistic/static secret can still be a leak.
            if not (
                positives
                & {
                    PositiveEvidence.REALISTIC_SECRET_SHAPE,
                    PositiveEvidence.PROVIDER_SPECIFIC_FORMAT,
                    PositiveEvidence.STRUCTURED_SECRET,
                    PositiveEvidence.HIGH_ENTROPY,
                }
            ):
                candidate.validation_state = ValidationState.REJECTED
                candidate.rejection_reason = "documentation_without_strong_value"
                return

        if PositiveEvidence.REALISTIC_SECRET_SHAPE in positives or (
            PositiveEvidence.STATIC_LITERAL in positives
            and PositiveEvidence.HIGH_ENTROPY in positives
        ):
            candidate.validation_state = ValidationState.CONFIRMED
            return

        if is_strong_secret_value(candidate.analysis_value):
            candidate.validation_state = ValidationState.CONFIRMED
            return

        if candidate.subtype == "username-field":
            candidate.validation_state = ValidationState.CANDIDATE_ONLY
            candidate.rejection_reason = "username_without_strong_secret"
            return

        candidate.validation_state = ValidationState.CANDIDATE_ONLY
        candidate.rejection_reason = "insufficient_positive_evidence"

    def _policy_correlated(self, candidate: SensitiveCandidate) -> None:
        user, password = pair_values(candidate.analysis_value or candidate.match.raw_value)
        if password is None or not is_strong_secret_value(password):
            candidate.validation_state = ValidationState.REJECTED
            candidate.rejection_reason = "correlated_credentials_weak_values"
            return
        if user is not None and not user.strip():
            candidate.validation_state = ValidationState.REJECTED
            candidate.rejection_reason = "correlated_credentials_weak_values"
            return
        _add_positive(candidate, PositiveEvidence.CREDENTIAL_PAIR)
        candidate.negative_evidence = [
            signal
            for signal in candidate.negative_evidence
            if signal
            not in {
                NegativeEvidence.PLACEHOLDER_VALUE,
                NegativeEvidence.WEAK_GENERIC_VALUE,
                NegativeEvidence.EXAMPLE_VALUE,
            }
        ]
        candidate.value_strength = ValueStrength.REALISTIC
        candidate.validation_state = ValidationState.CONFIRMED


def _add_negative(candidate: SensitiveCandidate, signal: NegativeEvidence) -> None:
    if signal not in candidate.negative_evidence:
        candidate.negative_evidence.append(signal)


def _add_positive(candidate: SensitiveCandidate, signal: PositiveEvidence) -> None:
    if signal not in candidate.positive_evidence:
        candidate.positive_evidence.append(signal)
