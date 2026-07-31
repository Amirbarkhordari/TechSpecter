"""Evidence quality gates for confirmed technology detection."""

from __future__ import annotations

from dataclasses import dataclass

from techspecter.fingerprinting.models import UNKNOWN_VERSION, PatternEvidence, TechnologyMatch
from techspecter.fingerprinting.scoring import MatchEvidence

MEDIUM_CONFIDENCE_THRESHOLD = 50.0
HIGH_CONFIDENCE_THRESHOLD = 70.0

# Patterns that frequently produce false positives on unrelated sites.
WEAK_PATTERN_KEYS: frozenset[tuple[str, str]] = frozenset(
    {
        ("global", "ng"),
        ("global", "l"),
        ("global", "bootstrap"),
        ("string", "bootstrap"),
        ("filename", "chunk"),
    }
)

# Unique framework markers that justify a single-pattern detection.
STRONG_PATTERN_KEYS: frozenset[tuple[str, str]] = frozenset(
    {
        ("string", "__webpack_require__"),
        ("string", "@angular/core"),
        ("regex", "angular\\.module"),
        ("regex", "ɵɵdefinecomponent"),
        ("string", "reactdom"),
        ("string", "react.production.min"),
        ("string", "next/dist"),
        ("string", "turbopack"),
        ("global", "webpackbootstrap"),
    }
)


def _pattern_key(matcher: str, pattern: str) -> tuple[str, str]:
    return (matcher.lower(), pattern.lower())


def is_weak_pattern(matcher: str, pattern: str) -> bool:
    """Return True when a matcher/pattern pair is considered weak evidence."""
    key = _pattern_key(matcher, pattern)
    if key in WEAK_PATTERN_KEYS:
        return True
    if matcher == "global" and len(pattern.strip()) <= 2:
        return True
    if matcher == "filename" and pattern.lower() == "chunk":
        return True
    if matcher == "string" and pattern.lower() == "bootstrap":
        return True
    return False


def is_strong_pattern(matcher: str, pattern: str) -> bool:
    """Return True when a matcher/pattern pair is strong standalone evidence."""
    key = _pattern_key(matcher, pattern)
    if key in STRONG_PATTERN_KEYS:
        return True
    if matcher == "regex" and pattern.startswith("__"):
        return True
    if matcher == "string" and (
        pattern.startswith("__")
        or pattern.startswith("@")
        or "version" in pattern.lower()
        or ".production." in pattern.lower()
    ):
        return True
    return False


def is_strong_evidence(item: PatternEvidence) -> bool:
    """Return True when structured evidence is strong enough to confirm alone."""
    if is_strong_pattern(item.matcher, item.pattern):
        return True
    if item.matcher in {"runtime", "javascript", "html"} and item.weight >= 70.0:
        return True
    if item.matcher == "regex" and item.weight >= 25.0:
        return True
    return False


@dataclass(slots=True)
class MatchQualityGate:
    """Filter technology matches to evidence-backed, confirmed detections."""

    medium_confidence: float = MEDIUM_CONFIDENCE_THRESHOLD
    high_confidence: float = HIGH_CONFIDENCE_THRESHOLD

    def is_confirmed(self, match: TechnologyMatch) -> bool:
        """Return True when a match should appear in confirmed output."""
        if not self._has_valid_source(match):
            return False
        if match.confidence < self.medium_confidence:
            return False

        patterns = self._collect_patterns(match)
        if not patterns:
            return False

        if self._has_resolved_version(match):
            return True

        strong_patterns = [item for item in patterns if is_strong_evidence(item)]
        if strong_patterns:
            return True

        if len(match.providers) >= 2 and match.confidence >= self.medium_confidence:
            non_weak = [
                item for item in patterns if not is_weak_pattern(item.matcher, item.pattern)
            ]
            if non_weak:
                return True

        non_weak = [
            item for item in patterns if not is_weak_pattern(item.matcher, item.pattern)
        ]
        if not non_weak:
            return False
        if len(non_weak) >= 2:
            return True
        if len(non_weak) == 1 and match.confidence >= self.high_confidence:
            return True
        return len(non_weak) == 1 and non_weak[0].weight >= 30.0

    def partition(
        self,
        matches: list[TechnologyMatch],
    ) -> tuple[list[TechnologyMatch], list[TechnologyMatch]]:
        """Split matches into confirmed and ignored (weak/unconfirmed) lists."""
        confirmed: list[TechnologyMatch] = []
        ignored: list[TechnologyMatch] = []
        for match in matches:
            if self.is_confirmed(match):
                confirmed.append(match)
            else:
                ignored.append(match)
        return confirmed, ignored

    def is_confirmable_evidence(
        self,
        evidence: MatchEvidence,
        *,
        confidence: float,
        version: str,
    ) -> bool:
        """Return True when raw engine evidence meets confirmation rules."""
        if not evidence.matched_patterns:
            return False
        if confidence < self.medium_confidence:
            return False
        if version != UNKNOWN_VERSION:
            return True
        if any(is_strong_pattern(item.matcher, item.pattern) for item in evidence.matched_patterns):
            return True
        non_weak = [
            item
            for item in evidence.matched_patterns
            if not is_weak_pattern(item.matcher, item.pattern)
        ]
        if not non_weak:
            return False
        if len(non_weak) >= 2:
            return True
        return len(non_weak) == 1 and non_weak[0].weight >= 30.0

    def _has_valid_source(self, match: TechnologyMatch) -> bool:
        filename = (match.filename or "").strip()
        if filename and filename.lower() not in {"unknown", ""}:
            return True
        if match.matched_resources:
            return True
        source_url = (match.source_url or "").strip()
        if source_url.startswith("http://") or source_url.startswith("https://"):
            return True
        for item in match.evidence:
            if item.detail and item.detail.lower() not in {"unknown", "-"}:
                if item.matcher in {"runtime", "javascript", "string", "regex", "filename"}:
                    return True
        return False

    def _has_resolved_version(self, match: TechnologyMatch) -> bool:
        if match.version == UNKNOWN_VERSION:
            return False
        version_confidence = match.version_confidence
        if version_confidence is not None and version_confidence >= 60.0:
            return True
        return match.confidence >= self.high_confidence

    def _collect_patterns(self, match: TechnologyMatch) -> list[PatternEvidence]:
        if match.evidence:
            return list(match.evidence)
        parsed: list[PatternEvidence] = []
        for entry in match.matched_patterns:
            matcher, _, pattern = entry.partition(":")
            if not matcher or not pattern:
                continue
            parsed.append(
                PatternEvidence(
                    matcher=matcher,
                    pattern=pattern,
                    weight=10.0,
                    detail=match.filename,
                )
            )
        return parsed


def apply_match_quality_gate(
    matches: list[TechnologyMatch],
    *,
    gate: MatchQualityGate | None = None,
) -> tuple[list[TechnologyMatch], list[TechnologyMatch]]:
    """Partition technology matches into confirmed and ignored groups."""
    quality_gate = gate or MatchQualityGate()
    return quality_gate.partition(matches)


def build_detection_reason(match: TechnologyMatch) -> str:
    """Build a concise human-readable detection reason from evidence."""
    patterns = MatchQualityGate()._collect_patterns(match)
    if not patterns:
        return match.detection_reason or ""
    primary = max(patterns, key=lambda item: item.weight)
    detail = primary.detail or match.filename or match.source_url or "discovered asset"
    return f"{primary.matcher}:{primary.pattern} @ {detail}"
