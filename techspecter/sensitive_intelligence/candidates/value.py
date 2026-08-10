"""Centralized value analysis for sensitive candidates."""

from __future__ import annotations

import re

from techspecter.sensitive_intelligence.candidates.builder import pair_values
from techspecter.sensitive_intelligence.candidates.models import (
    NegativeEvidence,
    PositiveEvidence,
    SensitiveCandidate,
    ValueStrength,
)
from techspecter.sensitive_intelligence.candidates.placeholders import (
    is_example_value,
    is_placeholder_value,
)
from techspecter.sensitive_intelligence.candidates.runtime import (
    is_empty_literal,
    is_form_reference,
    is_runtime_reference,
    is_self_reference,
    is_template_value,
)
from techspecter.sensitive_intelligence.detectors.entropy_secrets import shannon_entropy
from techspecter.sensitive_intelligence.rules.validators import (
    validate_aws_access_key,
    validate_github_token,
    validate_jwt,
    validate_pem,
)

_PROVIDER_PREFIXES = (
    "akia",
    "asia",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "rk_test_",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxr-",
    "aiza",
    "sk-ant-",
    "sk-",
    "glpat-",
    "sg.",
)

_WEAK_GENERIC_EXTRA = frozenset(
    {
        "password1",
        "password12",
        "password123",
        "password1234",
        "admin123",
        "welcome1",
        "letmein",
        "iloveyou",
        "abc123",
        "abc12345",
    },
)


class ValueAnalyzer:
    """Evaluate whether a matched value resembles real sensitive material."""

    def analyze(self, candidate: SensitiveCandidate) -> SensitiveCandidate:
        """Annotate candidate with value-based evidence (mutates and returns)."""
        if candidate.subtype == "correlated-credentials" or (
            candidate.subtype or ""
        ).startswith("correlated-"):
            return self._analyze_pair(candidate)

        value = candidate.analysis_value
        if value is None:
            value = candidate.match.raw_value
        if value is None:
            candidate.value_strength = ValueStrength.UNKNOWN
            return candidate

        stripped = value.strip()

        if is_empty_literal(stripped):
            _add_negative(candidate, NegativeEvidence.EMPTY_VALUE)
            candidate.value_strength = ValueStrength.EMPTY
            return candidate

        if is_form_reference(stripped):
            _add_negative(candidate, NegativeEvidence.FORM_REFERENCE)
            _add_negative(candidate, NegativeEvidence.FORM_FIELD)
            candidate.value_strength = ValueStrength.RUNTIME
            return candidate

        if is_template_value(stripped):
            _add_negative(candidate, NegativeEvidence.GENERATED_TEMPLATE)
            candidate.value_strength = ValueStrength.PLACEHOLDER

        if is_runtime_reference(stripped) and not _looks_like_structured_secret(stripped, candidate):
            _add_negative(candidate, NegativeEvidence.RUNTIME_REFERENCE)
            candidate.value_strength = ValueStrength.RUNTIME

        if is_self_reference(
            stripped,
            credential_name=candidate.credential_name,
            subtype=candidate.subtype,
        ):
            _add_negative(candidate, NegativeEvidence.SELF_REFERENCE)
            candidate.value_strength = ValueStrength.RUNTIME

        if is_placeholder_value(stripped):
            _add_negative(candidate, NegativeEvidence.PLACEHOLDER_VALUE)
            if is_example_value(stripped):
                _add_negative(candidate, NegativeEvidence.EXAMPLE_VALUE)
            candidate.value_strength = ValueStrength.PLACEHOLDER

        if _is_weak_generic(stripped):
            _add_negative(candidate, NegativeEvidence.WEAK_GENERIC_VALUE)
            if candidate.value_strength in {ValueStrength.UNKNOWN, ValueStrength.REALISTIC}:
                candidate.value_strength = ValueStrength.WEAK

        if _has_provider_format(stripped, candidate):
            _add_positive(candidate, PositiveEvidence.PROVIDER_SPECIFIC_FORMAT)
            _add_positive(candidate, PositiveEvidence.STRUCTURED_SECRET)
            candidate.value_strength = ValueStrength.STRUCTURED

        if (
            _looks_realistic(stripped)
            and NegativeEvidence.PLACEHOLDER_VALUE not in candidate.negative_evidence
            and NegativeEvidence.WEAK_GENERIC_VALUE not in candidate.negative_evidence
        ):
            _add_positive(candidate, PositiveEvidence.REALISTIC_SECRET_SHAPE)
            if candidate.value_strength in {ValueStrength.UNKNOWN, ValueStrength.WEAK}:
                candidate.value_strength = ValueStrength.REALISTIC

        entropy = shannon_entropy(stripped)
        if (
            entropy >= 4.0
            and len(stripped) >= 16
            and NegativeEvidence.PLACEHOLDER_VALUE not in candidate.negative_evidence
            and NegativeEvidence.WEAK_GENERIC_VALUE not in candidate.negative_evidence
        ):
            _add_positive(candidate, PositiveEvidence.HIGH_ENTROPY)

        if _quoted_static_secret(stripped) and not {
            NegativeEvidence.RUNTIME_REFERENCE,
            NegativeEvidence.FORM_REFERENCE,
            NegativeEvidence.SELF_REFERENCE,
            NegativeEvidence.EMPTY_VALUE,
        } & set(candidate.negative_evidence):
            _add_positive(candidate, PositiveEvidence.STATIC_LITERAL)

        if candidate.value_strength == ValueStrength.UNKNOWN:
            candidate.value_strength = ValueStrength.WEAK if _is_weak_generic(stripped) else (
                ValueStrength.REALISTIC if _looks_realistic(stripped) else ValueStrength.UNKNOWN
            )
        return candidate

    def _analyze_pair(self, candidate: SensitiveCandidate) -> SensitiveCandidate:
        user, password = pair_values(candidate.analysis_value or candidate.match.raw_value)
        if user is None or password is None:
            _add_negative(candidate, NegativeEvidence.EMPTY_VALUE)
            candidate.value_strength = ValueStrength.EMPTY
            return candidate

        _add_positive(candidate, PositiveEvidence.CREDENTIAL_PAIR)
        password_strength = ValueStrength.UNKNOWN
        for label, value in (("username", user), ("password", password)):
            if is_empty_literal(value):
                _add_negative(candidate, NegativeEvidence.EMPTY_VALUE)
                password_strength = ValueStrength.EMPTY
            elif is_placeholder_value(value) or _is_weak_generic(value):
                _add_negative(candidate, NegativeEvidence.WEAK_GENERIC_VALUE)
                if is_placeholder_value(value):
                    _add_negative(candidate, NegativeEvidence.PLACEHOLDER_VALUE)
                if label == "password":
                    password_strength = ValueStrength.PLACEHOLDER
            elif label == "password" and _looks_realistic(value):
                _add_positive(candidate, PositiveEvidence.REALISTIC_SECRET_SHAPE)
                _add_positive(candidate, PositiveEvidence.STATIC_LITERAL)
                password_strength = ValueStrength.REALISTIC
        candidate.value_strength = password_strength
        return candidate


def is_strong_secret_value(value: str | None) -> bool:
    """Return True when a value looks like a non-placeholder secret."""
    if value is None:
        return False
    stripped = value.strip()
    if is_empty_literal(stripped) or is_placeholder_value(stripped) or _is_weak_generic(stripped):
        return False
    if is_form_reference(stripped) or is_template_value(stripped) or is_runtime_reference(stripped):
        return False
    return _looks_realistic(stripped) or _has_provider_prefix(stripped)


def _is_weak_generic(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 6:
        return True
    lowered = stripped.lower()
    if is_placeholder_value(stripped) or lowered in _WEAK_GENERIC_EXTRA:
        return True
    if re.fullmatch(r"\d{4,12}", stripped):
        return True
    # Common weak patterns: password + digits, even if mixed-case entropy looks okay.
    if re.fullmatch(r"(?:password|passwd|pwd|secret|token)\d{0,6}!?", lowered):
        return True
    if re.fullmatch(r"[a-z]+", lowered) and len(lowered) <= 12:
        return True
    return False


def _looks_realistic(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 8:
        return False
    if is_placeholder_value(stripped) or _is_weak_generic(stripped):
        return False
    classes = sum(
        [
            any(c.islower() for c in stripped),
            any(c.isupper() for c in stripped),
            any(c.isdigit() for c in stripped),
            any(not c.isalnum() for c in stripped),
        ],
    )
    if classes >= 2 and len(stripped) >= 10:
        return True
    if classes >= 3 and len(stripped) >= 8:
        return True
    if len(stripped) >= 16 and shannon_entropy(stripped) >= 3.5:
        return True
    return _has_provider_prefix(stripped)


def _has_provider_prefix(value: str) -> bool:
    lowered = value.strip().lower()
    return any(lowered.startswith(prefix) for prefix in _PROVIDER_PREFIXES)


def _looks_like_structured_secret(value: str, candidate: SensitiveCandidate) -> bool:
    return _has_provider_format(value, candidate)


def _has_provider_format(value: str, candidate: SensitiveCandidate) -> bool:
    stripped = value.strip()
    rule_id = candidate.rule_id or candidate.subtype
    dummy = re.match(r".*", stripped)
    assert dummy is not None
    token = stripped
    if token.lower().startswith("bearer "):
        token = token.split(None, 1)[1]
    # Require JWT-shaped values (typically eyJ...) — not process.env.TOKEN.
    if rule_id in {"jwt-token", "bearer-token"} or _looks_like_jwt(token):
        if validate_jwt(token, dummy):
            return True
    if rule_id in {"private-key", "ssh-private-key", "certificate", "pem-block"}:
        if validate_pem(stripped, dummy):
            return True
    if rule_id == "aws-access-key" or stripped.startswith("AKIA"):
        if validate_aws_access_key(stripped, dummy):
            return True
    if rule_id == "github-token" or stripped.startswith(("ghp_", "github_pat_")):
        if validate_github_token(stripped, dummy):
            return True
    return _has_provider_prefix(stripped)


def _looks_like_jwt(value: str) -> bool:
    if value.count(".") != 2:
        return False
    return value.startswith("eyJ")


def _quoted_static_secret(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return False
    if is_runtime_reference(stripped) or is_form_reference(stripped) or is_self_reference(stripped):
        return False
    return True


def _add_positive(candidate: SensitiveCandidate, signal: PositiveEvidence) -> None:
    if signal not in candidate.positive_evidence:
        candidate.positive_evidence.append(signal)


def _add_negative(candidate: SensitiveCandidate, signal: NegativeEvidence) -> None:
    if signal not in candidate.negative_evidence:
        candidate.negative_evidence.append(signal)
