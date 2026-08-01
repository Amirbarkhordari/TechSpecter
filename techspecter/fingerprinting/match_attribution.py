"""Evidence attribution helpers for technology detection."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from techspecter.fingerprinting.models import (
    UNKNOWN_VERSION,
    FingerprintPattern,
    PatternEvidence,
    TechnologyMatch,
)

if TYPE_CHECKING:
    from techspecter.fingerprinting.context import MatchContext

_EVIDENCE_SNIPPET_MAX = 120
_VERSION_EVIDENCE_TYPE = "version_marker"


def extract_matched_value(
    pattern: FingerprintPattern,
    content: str,
    *,
    filename: str | None = None,
) -> str | None:
    """Extract a representative matched value from analyzed content."""
    if pattern.matcher == "filename":
        return filename or pattern.pattern

    if pattern.matcher == "string":
        if pattern.pattern in content:
            return _truncate(pattern.pattern)
        return None

    if pattern.matcher == "global":
        return pattern.pattern

    if pattern.matcher == "regex":
        flags = re.IGNORECASE if pattern.flags and "i" in pattern.flags.lower() else 0
        compiled = re.compile(pattern.pattern, flags)
        match = compiled.search(content)
        if match is None:
            return None
        if match.lastindex and match.lastindex >= 1:
            return _truncate(match.group(1))
        return _truncate(match.group(0))

    return pattern.pattern


def build_pattern_evidence(
    pattern: FingerprintPattern,
    context: MatchContext,
    *,
    evidence_type: str = "fingerprint_pattern",
    matched_value: str | None = None,
) -> PatternEvidence:
    """Build structured evidence tied to an analyzed asset."""
    resolved_value = matched_value or extract_matched_value(
        pattern,
        context.content,
        filename=context.filename,
    )
    return PatternEvidence(
        matcher=pattern.matcher,
        pattern=pattern.pattern,
        weight=pattern.weight,
        detail=resolved_value or context.filename,
        source_file=context.filename,
        asset_id=context.asset_id,
        evidence_type=evidence_type,
        matched_value=resolved_value,
    )


def build_version_evidence(
    *,
    matcher: str,
    pattern: str,
    matched_value: str,
    context: MatchContext,
    weight: float,
) -> PatternEvidence:
    """Build version attribution evidence without altering version extraction."""
    return PatternEvidence(
        matcher=matcher,
        pattern=pattern,
        weight=weight,
        detail=matched_value,
        source_file=context.filename,
        asset_id=context.asset_id,
        evidence_type=_VERSION_EVIDENCE_TYPE,
        matched_value=matched_value,
    )


def merge_evidence_items(items: list[PatternEvidence]) -> list[PatternEvidence]:
    """Merge evidence entries preserving distinct source files."""
    merged: dict[tuple[str, str, str | None], PatternEvidence] = {}
    for item in items:
        source = item.source_file or item.detail
        key = (item.matcher.lower(), item.pattern.lower(), source)
        existing = merged.get(key)
        if existing is None or item.weight > existing.weight:
            merged[key] = item
    return sorted(
        merged.values(),
        key=lambda entry: (-entry.weight, entry.matcher, entry.pattern),
    )


def apply_match_attribution(match: TechnologyMatch) -> TechnologyMatch:
    """Populate top-level attribution fields from structured evidence."""
    if not match.evidence:
        source_file = match.filename or match.source_file
        if source_file is None and not match.source_url:
            return match
        return match.model_copy(
            update={
                "source_file": source_file,
                "asset_id": match.asset_id,
            },
        )

    primary = max(match.evidence, key=lambda item: item.weight)
    source_file = match.filename or primary.source_file or match.source_file
    asset_id = match.asset_id or primary.asset_id
    matched_value = primary.matched_value or primary.detail

    return match.model_copy(
        update={
            "source_file": source_file,
            "asset_id": asset_id,
            "primary_matcher": primary.matcher,
            "primary_pattern": primary.pattern,
            "matched_value": matched_value,
            "evidence_count": len(match.evidence),
            "detection_reason": _build_detection_reason(primary, source_file),
        },
    )


def has_attributed_evidence(match: TechnologyMatch) -> bool:
    """Return True when detection evidence references an analyzed asset."""
    if _valid_asset_source(match.filename):
        return True
    if _valid_asset_source(match.source_file):
        return True
    if match.source_url and (
        match.source_url.startswith("http://") or match.source_url.startswith("https://")
    ):
        return True
    return bool(
        match.source_url
        and match.source_url.startswith("inline://")
        and match.evidence
    )


def has_structured_evidence(match: TechnologyMatch) -> bool:
    """Return True when a detection includes matcher-produced evidence."""
    if match.evidence:
        return True
    return bool(match.matched_patterns)


def is_valid_detection_candidate(match: TechnologyMatch) -> bool:
    """Return True when a match satisfies foundation evidence requirements."""
    return has_structured_evidence(match) and has_attributed_evidence(match)


def select_best_version_match(matches: list[TechnologyMatch]) -> TechnologyMatch | None:
    """Select the match carrying the strongest known version attribution."""
    known = [item for item in matches if item.version not in (UNKNOWN_VERSION, "", None)]
    if not known:
        return None
    return max(
        known,
        key=lambda item: (
            item.version_confidence or 0.0,
            item.confidence,
        ),
    )


def _build_detection_reason(primary: PatternEvidence, source_file: str | None) -> str:
    source = source_file or primary.source_file or "discovered asset"
    value = primary.matched_value or primary.pattern
    return f"{primary.matcher}:{value} @ {source}"


def _valid_asset_source(value: str | None) -> bool:
    if value is None:
        return False
    normalized = value.strip().lower()
    return normalized not in {"", "unknown"}


def _truncate(value: str, limit: int = _EVIDENCE_SNIPPET_MAX) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."
