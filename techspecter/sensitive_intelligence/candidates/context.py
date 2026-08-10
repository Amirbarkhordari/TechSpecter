"""Lightweight context analysis for sensitive candidates."""

from __future__ import annotations

import re

from techspecter.sensitive_intelligence.candidates.models import (
    NegativeEvidence,
    PositiveEvidence,
    SensitiveCandidate,
)

_STATIC_ASSIGNMENT = re.compile(
    r"""(?:password|passwd|pwd|username|user_name|login|token|secret|api[_-]?key|key|sid)"""
    r"""\s*[:=]\s*['\"][^'\"]+['\"]""",
    re.I,
)
_EMPTY_ASSIGNMENT = re.compile(
    r"""(?:password|passwd|pwd|username|user_name|login|token|secret|api[_-]?key)"""
    r"""\s*[:=]\s*['\"]\s*['\"]""",
    re.I,
)
_RUNTIME_REF = re.compile(
    r"""(?:password|passwd|pwd|username|user_name|login|token|secret|api[_-]?key|key)"""
    r"""\s*[:=]\s*(?!['\"])"""
    r"""([A-Za-z_$][\w.$]*(?:\([^)]*\))?)\s*[,;}\n)]""",
    re.I,
)
_FORM_REF = re.compile(
    r"""(?:form\.[A-Za-z_][\w.]*\.value|[A-Za-z_][\w.]*\.password\.value)"""
    r"""|getElementById\([^)]+\)\.value|querySelector\([^)]+\)\.value""",
    re.I,
)
_HTML_PASSWORD_ATTR = re.compile(
    r"""(?:type\s*=\s*['\"]password['\"]|name\s*=\s*['\"]password['\"])""",
    re.I,
)
_DOC_MARKERS = re.compile(
    r"""(?://|/\*|\*|#)\s*(?:example|e\.g\.|sample|todo|fixme|note:)|"""
    r"""\b(?:for example|example usage|documentation|docs?)\b""",
    re.I,
)
_TEST_MARKERS = re.compile(
    r"""\b(?:describe\(|it\(|test\(|pytest|unittest|fixture|mock(?:ed)?|stub)\b""",
    re.I,
)
_TEMPLATE_MARKERS = re.compile(
    r"""(?:\{\{[^}]+\}\}|\$\{[^}]+\}|<%=?[^%]+%>|__\w+__|<<\w+>>)""",
)
_CONFIG_OBJECT = re.compile(
    r"""(?:config|settings|credentials|auth|env|process\.env)\b""",
    re.I,
)


class ContextAnalyzer:
    """Identify contextual positive/negative signals around a candidate."""

    def analyze(self, candidate: SensitiveCandidate) -> SensitiveCandidate:
        """Annotate candidate with context evidence (mutates and returns)."""
        text = " ".join(
            part
            for part in (candidate.evidence, candidate.match.raw_value, candidate.analysis_value)
            if part
        )
        if not text:
            return candidate

        if _HTML_PASSWORD_ATTR.search(text) and candidate.subtype in {
            "password-field",
            "username-field",
        }:
            _add_negative(candidate, NegativeEvidence.HTML_ATTRIBUTE)

        if _EMPTY_ASSIGNMENT.search(text):
            _add_negative(candidate, NegativeEvidence.EMPTY_VALUE)

        if _FORM_REF.search(text) or (
            candidate.analysis_value and _FORM_REF.search(candidate.analysis_value)
        ):
            _add_negative(candidate, NegativeEvidence.FORM_REFERENCE)

        runtime = _RUNTIME_REF.search(text)
        if runtime:
            ref = runtime.group(1)
            if not _looks_like_string_literal_context(text):
                _add_negative(candidate, NegativeEvidence.RUNTIME_REFERENCE)
                if _is_self_reference(candidate, ref):
                    _add_negative(candidate, NegativeEvidence.SELF_REFERENCE)

        value = candidate.analysis_value or ""
        if value and _FORM_REF.search(value):
            _add_negative(candidate, NegativeEvidence.FORM_REFERENCE)
        if (
            value
            and re.fullmatch(r"[A-Za-z_$][\w.$]*", value)
            and "." in value
            and value.count(".") != 2
            and len(value) < 24
        ):
            _add_negative(candidate, NegativeEvidence.RUNTIME_REFERENCE)

        if _DOC_MARKERS.search(text):
            _add_negative(candidate, NegativeEvidence.DOCUMENTATION_CONTEXT)
        if _TEST_MARKERS.search(text):
            _add_negative(candidate, NegativeEvidence.TEST_FIXTURE)
        if _TEMPLATE_MARKERS.search(text) or (
            value and _TEMPLATE_MARKERS.search(value)
        ):
            _add_negative(candidate, NegativeEvidence.GENERATED_TEMPLATE)

        if _STATIC_ASSIGNMENT.search(text) or _quoted_literal(value):
            _add_positive(candidate, PositiveEvidence.STATIC_LITERAL)
        if _CONFIG_OBJECT.search(text):
            _add_positive(candidate, PositiveEvidence.CONFIGURATION_ASSIGNMENT)

        return candidate


def _quoted_literal(value: str) -> bool:
    return bool(value) and not re.fullmatch(r"[A-Za-z_$][\w.$]*", value)


def _looks_like_string_literal_context(text: str) -> bool:
    return bool(_STATIC_ASSIGNMENT.search(text))


def _is_self_reference(candidate: SensitiveCandidate, ref: str) -> bool:
    token = ref.split(".")[-1].lower()
    subtype = (candidate.subtype or "").lower()
    return token in {subtype, "token", "password", "secret", "key", "username"}


def _add_positive(candidate: SensitiveCandidate, signal: PositiveEvidence) -> None:
    if signal not in candidate.positive_evidence:
        candidate.positive_evidence.append(signal)


def _add_negative(candidate: SensitiveCandidate, signal: NegativeEvidence) -> None:
    if signal not in candidate.negative_evidence:
        candidate.negative_evidence.append(signal)
