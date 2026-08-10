"""Lightweight context analysis for sensitive candidates."""

from __future__ import annotations

import re

from techspecter.sensitive_intelligence.candidates.models import (
    ContextKind,
    NegativeEvidence,
    PositiveEvidence,
    SensitiveCandidate,
)
from techspecter.sensitive_intelligence.candidates.placeholders import (
    is_example_value,
    is_placeholder_value,
)
from techspecter.sensitive_intelligence.candidates.runtime import (
    extract_runtime_target,
    is_empty_literal,
    is_form_reference,
    is_runtime_reference,
    is_self_reference,
    is_template_value,
)

_STATIC_ASSIGNMENT = re.compile(
    r"""(?:password|passwd|pwd|username|user_name|login|token|secret|api[_-]?key|key|sid|"""
    r"""client_secret|access_key)"""
    r"""\s*[:=]\s*['\"][^'\"]+['\"]""",
    re.I,
)
_EMPTY_ASSIGNMENT = re.compile(
    r"""(?:password|passwd|pwd|username|user_name|login|token|secret|api[_-]?key|client_secret)"""
    r"""\s*[:=]\s*(?:['\"]\s*['\"]|null|undefined|None)\b""",
    re.I,
)
_HTML_PASSWORD_ATTR = re.compile(
    r"""(?:<\s*input\b[^>]*\btype\s*=\s*['\"]password['\"]"""
    r"""|\btype\s*=\s*['\"]password['\"]"""
    r"""|\bname\s*=\s*['\"]password['\"])""",
    re.I,
)
_DOC_MARKERS = re.compile(
    r"""(?://|/\*|\*|#)\s*(?:example|e\.g\.|sample|usage|note:)|"""
    r"""\b(?:for example|example usage|example configuration|readme|documentation)\b|"""
    r"""^\s*(?:example|sample)\s*[:\-]""",
    re.I | re.M,
)
_TEST_MARKERS = re.compile(
    r"""\b(?:describe\(|it\(|test\(|pytest|unittest|fixture_|mock_|sample_|"""
    r"""fake_|stub_|mock(?:ed)?_?(?:token|password|secret|key)|"""
    r"""fixture(?:_password|_token|_secret|_key)?)\b""",
    re.I,
)
_CONFIG_OBJECT = re.compile(
    r"""\b(?:config|settings|credentials|auth|runtimeConfig)\b""",
    re.I,
)


class ContextAnalyzer:
    """Identify contextual positive/negative signals around a candidate."""

    def analyze(self, candidate: SensitiveCandidate) -> SensitiveCandidate:
        """Annotate candidate with context evidence (mutates and returns)."""
        evidence = candidate.evidence or ""
        value = candidate.analysis_value
        text = " ".join(
            part for part in (evidence, candidate.match.raw_value, value) if part
        )
        if not text and value is None:
            return candidate

        kinds: list[ContextKind] = []

        if _HTML_PASSWORD_ATTR.search(text):
            _add_negative(candidate, NegativeEvidence.HTML_ATTRIBUTE)
            _add_negative(candidate, NegativeEvidence.FORM_FIELD)
            kinds.append(ContextKind.FORM_FIELD)
            candidate.context_kind = ContextKind.FORM_FIELD
            return candidate

        if _EMPTY_ASSIGNMENT.search(text) or is_empty_literal(value):
            _add_negative(candidate, NegativeEvidence.EMPTY_VALUE)
            kinds.append(ContextKind.EMPTY_ASSIGNMENT)

        if is_form_reference(value, evidence=evidence):
            _add_negative(candidate, NegativeEvidence.FORM_REFERENCE)
            _add_negative(candidate, NegativeEvidence.FORM_FIELD)
            kinds.append(ContextKind.FORM_FIELD)

        if is_self_reference(
            value,
            evidence=evidence,
            credential_name=candidate.credential_name,
            subtype=candidate.subtype,
        ):
            _add_negative(candidate, NegativeEvidence.SELF_REFERENCE)
            kinds.append(ContextKind.SELF_REFERENCE)

        runtime_hit = is_runtime_reference(value, evidence=evidence)
        if runtime_hit and not _STATIC_ASSIGNMENT.search(evidence):
            _add_negative(candidate, NegativeEvidence.RUNTIME_REFERENCE)
            kinds.append(ContextKind.RUNTIME_REFERENCE)
            # Preserve RHS for provenance/debugging when available.
            target = extract_runtime_target(evidence)
            if target and candidate.analysis_value is None:
                candidate.analysis_value = target

        if is_template_value(value) or (
            value is None and re.search(r"\{\{|\$\{|<%", evidence)
        ):
            _add_negative(candidate, NegativeEvidence.GENERATED_TEMPLATE)
            kinds.append(ContextKind.GENERATED_TEMPLATE)

        if value is not None and is_placeholder_value(value):
            _add_negative(candidate, NegativeEvidence.PLACEHOLDER_VALUE)
            kinds.append(ContextKind.PLACEHOLDER_ASSIGNMENT)
            if is_example_value(value):
                _add_negative(candidate, NegativeEvidence.EXAMPLE_VALUE)

        if _DOC_MARKERS.search(text):
            _add_negative(candidate, NegativeEvidence.DOCUMENTATION_CONTEXT)
            kinds.append(ContextKind.DOCUMENTATION)

        if _TEST_MARKERS.search(text) or _fixture_name_signal(candidate):
            _add_negative(candidate, NegativeEvidence.TEST_FIXTURE)
            kinds.append(ContextKind.TEST_FIXTURE)

        if _STATIC_ASSIGNMENT.search(evidence) or _quoted_static_literal(value):
            # Only treat as positive static when not already a runtime/form/empty shell.
            if not {
                ContextKind.RUNTIME_REFERENCE,
                ContextKind.FORM_FIELD,
                ContextKind.EMPTY_ASSIGNMENT,
                ContextKind.SELF_REFERENCE,
            } & set(kinds):
                _add_positive(candidate, PositiveEvidence.STATIC_LITERAL)
                _add_positive(candidate, PositiveEvidence.STATIC_ASSIGNMENT)
                kinds.append(ContextKind.STATIC_ASSIGNMENT)

        if _CONFIG_OBJECT.search(text) and ContextKind.RUNTIME_REFERENCE not in kinds:
            _add_positive(candidate, PositiveEvidence.CONFIGURATION_ASSIGNMENT)
            kinds.append(ContextKind.CONFIGURATION)

        candidate.context_kind = _primary_kind(kinds)
        return candidate


def _fixture_name_signal(candidate: SensitiveCandidate) -> bool:
    name = (candidate.credential_name or "").lower()
    evidence = (candidate.evidence or "").lower()
    return bool(
        re.search(
            r"\b(?:fixture_|mock_|sample_|fake_|stub_)(?:password|token|secret|key|api)",
            evidence,
        )
        or name.startswith(("fixture_", "mock_", "sample_", "fake_"))
    )


def _quoted_static_literal(value: str | None) -> bool:
    if not value:
        return False
    stripped = value.strip()
    if is_empty_literal(stripped) or is_runtime_reference(stripped) or is_form_reference(stripped):
        return False
    if is_placeholder_value(stripped) or is_template_value(stripped):
        return False
    return not re.fullmatch(r"[A-Za-z_$][\w.$]*", stripped) or stripped.count(".") == 2


def _primary_kind(kinds: list[ContextKind]) -> ContextKind:
    priority = (
        ContextKind.EMPTY_ASSIGNMENT,
        ContextKind.SELF_REFERENCE,
        ContextKind.FORM_FIELD,
        ContextKind.RUNTIME_REFERENCE,
        ContextKind.GENERATED_TEMPLATE,
        ContextKind.PLACEHOLDER_ASSIGNMENT,
        ContextKind.DOCUMENTATION,
        ContextKind.TEST_FIXTURE,
        ContextKind.STATIC_ASSIGNMENT,
        ContextKind.CONFIGURATION,
    )
    for kind in priority:
        if kind in kinds:
            return kind
    return ContextKind.UNKNOWN


def _add_positive(candidate: SensitiveCandidate, signal: PositiveEvidence) -> None:
    if signal not in candidate.positive_evidence:
        candidate.positive_evidence.append(signal)


def _add_negative(candidate: SensitiveCandidate, signal: NegativeEvidence) -> None:
    if signal not in candidate.negative_evidence:
        candidate.negative_evidence.append(signal)
