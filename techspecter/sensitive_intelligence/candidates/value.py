"""Centralized value analysis for sensitive candidates."""

from __future__ import annotations

import re

from techspecter.sensitive_intelligence.candidates.builder import pair_values
from techspecter.sensitive_intelligence.candidates.models import (
    NegativeEvidence,
    PositiveEvidence,
    SensitiveCandidate,
)
from techspecter.sensitive_intelligence.detectors.entropy_secrets import shannon_entropy
from techspecter.sensitive_intelligence.rules.validators import (
    validate_aws_access_key,
    validate_github_token,
    validate_jwt,
    validate_pem,
)

_PLACEHOLDER_VALUES = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "apikey",
        "api_key",
        "api-key",
        "changeme",
        "change_me",
        "changeit",
        "placeholder",
        "example",
        "sample",
        "test",
        "testing",
        "dummy",
        "fake",
        "default",
        "null",
        "none",
        "undefined",
        "your_password",
        "your-password",
        "your_password_here",
        "your-password-here",
        "insert_password",
        "insert-password",
        "xxx",
        "xxxx",
        "xxxxx",
        "todo",
        "fixme",
        "redacted",
        "secret123",
        "password123",
        "passw0rd",
        "123456",
        "12345678",
        "123456789",
        "qwerty",
        "admin",
        "root",
        "user",
        "username",
        "login",
        "guest",
        "invalid_password",
        "invalid-password",
    },
)

_PLACEHOLDER_PREFIXES = (
    "your_",
    "your-",
    "example_",
    "example-",
    "sample_",
    "sample-",
    "test_",
    "test-",
    "dummy_",
    "fake_",
    "replace_",
    "insert_",
    "<",
    "{{",
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

_FORM_LIKE = re.compile(
    r"""^(?:form\.[A-Za-z_][\w.]*|.*\.password\.value|[A-Za-z_$][\w]*\([^)]*\))$""",
    re.I,
)
_RUNTIME_LIKE = re.compile(r"""^[A-Za-z_$][\w.$]*$""")
_TEMPLATE_LIKE = re.compile(r"""(?:\{\{.*\}\}|\$\{.*\}|<%.*%>|^__\w+__$|^<<\w+>>$)""")


class ValueAnalyzer:
    """Evaluate whether a matched value resembles real sensitive material."""

    def analyze(self, candidate: SensitiveCandidate) -> SensitiveCandidate:
        """Annotate candidate with value-based evidence (mutates and returns)."""
        if candidate.subtype == "correlated-credentials":
            return self._analyze_pair(candidate)

        value = candidate.analysis_value
        if value is None:
            # Structured matches (JWT/PEM/provider) often keep full raw_value.
            value = candidate.match.raw_value

        if value is None:
            return candidate

        stripped = value.strip()
        if stripped == "" or stripped in {'""', "''"}:
            _add_negative(candidate, NegativeEvidence.EMPTY_VALUE)
            return candidate

        if _FORM_LIKE.match(stripped) or stripped.endswith(".value"):
            _add_negative(candidate, NegativeEvidence.FORM_REFERENCE)
            return candidate

        if _TEMPLATE_LIKE.search(stripped):
            _add_negative(candidate, NegativeEvidence.GENERATED_TEMPLATE)

        if _is_placeholder(stripped):
            _add_negative(candidate, NegativeEvidence.PLACEHOLDER_VALUE)
            if "example" in stripped.lower() or "sample" in stripped.lower():
                _add_negative(candidate, NegativeEvidence.EXAMPLE_VALUE)

        if _is_weak_generic(stripped):
            _add_negative(candidate, NegativeEvidence.WEAK_GENERIC_VALUE)

        if _RUNTIME_LIKE.match(stripped) and "." in stripped:
            # JWTs and other dotted secrets look like identifiers; do not treat as refs.
            if not (
                stripped.count(".") == 2
                or _has_provider_prefix(stripped)
                or (len(stripped) >= 20 and shannon_entropy(stripped) >= 3.5)
            ):
                _add_negative(candidate, NegativeEvidence.RUNTIME_REFERENCE)

        if _is_self_assignment(candidate, stripped):
            _add_negative(candidate, NegativeEvidence.SELF_REFERENCE)

        if _has_provider_format(stripped, candidate):
            _add_positive(candidate, PositiveEvidence.PROVIDER_SPECIFIC_FORMAT)
            _add_positive(candidate, PositiveEvidence.STRUCTURED_SECRET)

        if _looks_realistic(stripped) and NegativeEvidence.PLACEHOLDER_VALUE not in (
            candidate.negative_evidence
        ):
            _add_positive(candidate, PositiveEvidence.REALISTIC_SECRET_SHAPE)

        entropy = shannon_entropy(stripped)
        if entropy >= 4.0 and len(stripped) >= 16:
            _add_positive(candidate, PositiveEvidence.HIGH_ENTROPY)

        if _quoted_static_secret(stripped):
            _add_positive(candidate, PositiveEvidence.STATIC_LITERAL)

        return candidate

    def _analyze_pair(self, candidate: SensitiveCandidate) -> SensitiveCandidate:
        user, password = pair_values(candidate.analysis_value or candidate.match.raw_value)
        if user is None or password is None:
            _add_negative(candidate, NegativeEvidence.EMPTY_VALUE)
            return candidate

        _add_positive(candidate, PositiveEvidence.CREDENTIAL_PAIR)
        for label, value in (("username", user), ("password", password)):
            if not value.strip():
                _add_negative(candidate, NegativeEvidence.EMPTY_VALUE)
            elif _is_placeholder(value) or _is_weak_generic(value):
                _add_negative(candidate, NegativeEvidence.WEAK_GENERIC_VALUE)
                if _is_placeholder(value):
                    _add_negative(candidate, NegativeEvidence.PLACEHOLDER_VALUE)
            elif label == "password" and _looks_realistic(value):
                _add_positive(candidate, PositiveEvidence.REALISTIC_SECRET_SHAPE)
                _add_positive(candidate, PositiveEvidence.STATIC_LITERAL)
        return candidate


def is_strong_secret_value(value: str | None) -> bool:
    """Return True when a value looks like a non-placeholder secret."""
    if value is None:
        return False
    stripped = value.strip()
    if not stripped or _is_placeholder(stripped) or _is_weak_generic(stripped):
        return False
    if _FORM_LIKE.match(stripped) or _TEMPLATE_LIKE.search(stripped):
        return False
    return _looks_realistic(stripped) or _has_provider_prefix(stripped)


def _is_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    if lowered in _PLACEHOLDER_VALUES:
        return True
    if any(lowered.startswith(prefix) for prefix in _PLACEHOLDER_PREFIXES):
        return True
    if re.fullmatch(r"x{3,}", lowered):
        return True
    if re.fullmatch(r"[*]{3,}", value.strip()):
        return True
    return False


def _is_weak_generic(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 6:
        return True
    lowered = stripped.lower()
    if lowered in _PLACEHOLDER_VALUES:
        return True
    if re.fullmatch(r"\d{4,10}", stripped):
        return True
    if re.fullmatch(r"[a-z]+", lowered) and len(lowered) <= 10:
        return True
    return False


def _looks_realistic(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 8:
        return False
    if _is_placeholder(stripped):
        return False
    classes = sum(
        [
            any(c.islower() for c in stripped),
            any(c.isupper() for c in stripped),
            any(c.isdigit() for c in stripped),
            any(not c.isalnum() for c in stripped),
        ],
    )
    if classes >= 2 and len(stripped) >= 8:
        return True
    if len(stripped) >= 16 and shannon_entropy(stripped) >= 3.5:
        return True
    return _has_provider_prefix(stripped)


def _has_provider_prefix(value: str) -> bool:
    lowered = value.strip().lower()
    return any(lowered.startswith(prefix) for prefix in _PROVIDER_PREFIXES)


def _has_provider_format(value: str, candidate: SensitiveCandidate) -> bool:
    stripped = value.strip()
    rule_id = candidate.rule_id or candidate.subtype
    dummy = re.match(r".*", stripped)
    assert dummy is not None
    if rule_id in {"jwt-token", "bearer-token"} or stripped.count(".") == 2:
        if validate_jwt(stripped, dummy):
            return True
        # Bearer may wrap a JWT.
        token = stripped
        if token.lower().startswith("bearer "):
            token = token.split(None, 1)[1]
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


def _is_self_assignment(candidate: SensitiveCandidate, value: str) -> bool:
    token = value.strip().lower()
    keys = {
        "token",
        "password",
        "passwd",
        "secret",
        "key",
        "apikey",
        "api_key",
        "username",
        candidate.subtype.lower().replace("-", "_"),
    }
    return token in keys


def _quoted_static_secret(value: str) -> bool:
    return bool(value) and not _RUNTIME_LIKE.fullmatch(value.strip())


def _add_positive(candidate: SensitiveCandidate, signal: PositiveEvidence) -> None:
    if signal not in candidate.positive_evidence:
        candidate.positive_evidence.append(signal)


def _add_negative(candidate: SensitiveCandidate, signal: NegativeEvidence) -> None:
    if signal not in candidate.negative_evidence:
        candidate.negative_evidence.append(signal)
