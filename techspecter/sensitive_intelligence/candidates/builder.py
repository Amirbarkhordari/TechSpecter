"""Build SensitiveCandidate objects from DetectorMatch evidence."""

from __future__ import annotations

import re

from techspecter.sensitive_intelligence.candidates.models import SensitiveCandidate
from techspecter.sensitive_intelligence.detectors.base import DetectorMatch
from techspecter.sensitive_intelligence.sources import TextAssetSource

_ASSIGNED_LITERAL = re.compile(
    r"""(?:password|passwd|pwd|username|user_name|login|token|secret|api[_-]?key|key|sid)"""
    r"""\s*[:=]\s*['\"]([^'\"]*)['\"]""",
    re.I,
)
_GENERIC_LITERAL = re.compile(r"""[:=]\s*['\"]([^'\"]*)['\"]""")
_BEARER_VALUE = re.compile(r"Bearer\s+([A-Za-z0-9._~+/=-]{8,})", re.I)
_PAIR_SPLIT = re.compile(r"\n")


def build_candidate(
    match: DetectorMatch,
    *,
    detector_id: str,
    source: TextAssetSource,
) -> SensitiveCandidate:
    """Wrap a detector match as a pending sensitive candidate."""
    analysis_value = _resolve_analysis_value(match)
    return SensitiveCandidate(
        match=match,
        detector_id=detector_id,
        source_url=source.url,
        source_file=source.filename,
        relative_path=source.relative_path,
        asset_id=source.asset_id,
        analysis_value=analysis_value,
        original_confidence=match.confidence,
        original_severity=match.severity,
        adjusted_confidence=match.confidence,
    )


def _resolve_analysis_value(match: DetectorMatch) -> str | None:
    """Prefer raw_value, then parse evidence for assigned literals."""
    if match.raw_value is not None:
        if match.subtype == "correlated-credentials":
            return match.raw_value
        extracted = _extract_assigned_literal(match.raw_value)
        return extracted if extracted is not None else match.raw_value

    if not match.evidence:
        if "[redacted]" in match.matched_value:
            return None
        return match.matched_value

    evidence = match.evidence
    if match.subtype == "bearer-token":
        bearer = _BEARER_VALUE.search(evidence)
        if bearer:
            return bearer.group(1)

    assigned = _extract_assigned_literal(evidence)
    if assigned is not None:
        return assigned

    if "[redacted]" not in match.matched_value:
        return match.matched_value
    return None


def _extract_assigned_literal(text: str) -> str | None:
    """Extract a quoted assignment value from raw match text or evidence."""
    if match := _ASSIGNED_LITERAL.search(text):
        return match.group(1)
    if match := _GENERIC_LITERAL.search(text):
        return match.group(1)
    if match := _BEARER_VALUE.search(text):
        return match.group(1)
    return None


def pair_values(raw_value: str | None) -> tuple[str | None, str | None]:
    """Split correlated username/password raw values."""
    if not raw_value:
        return None, None
    parts = _PAIR_SPLIT.split(raw_value, maxsplit=1)
    if len(parts) != 2:
        return None, None
    return parts[0], parts[1]
