"""Confidence scoring for fingerprint matches."""

from __future__ import annotations

from dataclasses import dataclass, field

from techspecter.fingerprinting.models import (
    UNKNOWN_VERSION,
    Fingerprint,
    FingerprintPattern,
    VersionPattern,
)

MATCHER_MULTIPLIERS: dict[str, float] = {
    "global": 1.25,
    "regex": 1.15,
    "string": 1.0,
    "sourcemap": 0.95,
    "filename": 0.85,
}


@dataclass(frozen=True, slots=True)
class MatchEvidence:
    """Evidence collected during fingerprint matching."""

    matched_patterns: list[FingerprintPattern]
    version_pattern: VersionPattern | None = None


@dataclass(slots=True)
class ConfidenceScorer:
    """Calculate normalized confidence scores for technology matches."""

    min_confidence: float = 50.0
    matcher_multipliers: dict[str, float] = field(default_factory=lambda: dict(MATCHER_MULTIPLIERS))

    def score(self, fingerprint: Fingerprint, evidence: MatchEvidence, version: str) -> float:
        """Calculate a normalized confidence score from 0 to 100."""
        earned = sum(self._weighted_pattern_score(pattern) for pattern in evidence.matched_patterns)
        max_possible = sum(
            self._weighted_pattern_score(pattern) for pattern in fingerprint.patterns
        )

        if evidence.version_pattern is not None and version != UNKNOWN_VERSION:
            earned += evidence.version_pattern.weight * 1.2
            max_possible += sum(item.weight for item in fingerprint.version_patterns) * 1.2

        if max_possible <= 0:
            return min(100.0, fingerprint.confidence)

        normalized = (earned / max_possible) * 100.0
        blended = (normalized * 0.75) + (fingerprint.confidence * 0.25)
        adjusted = self._apply_match_quality_rules(blended, evidence)
        return round(min(100.0, max(0.0, adjusted)), 2)

    def passes_threshold(self, confidence: float) -> bool:
        """Return whether a confidence score meets the minimum threshold."""
        return confidence >= self.min_confidence

    def _weighted_pattern_score(self, pattern: FingerprintPattern) -> float:
        """Apply matcher-type multiplier to a pattern weight."""
        multiplier = self.matcher_multipliers.get(pattern.matcher, 1.0)
        return pattern.weight * multiplier

    def _apply_match_quality_rules(self, score: float, evidence: MatchEvidence) -> float:
        """Adjust score based on match quality heuristics."""
        from techspecter.fingerprinting.match_quality import is_weak_pattern

        matchers = {pattern.matcher for pattern in evidence.matched_patterns}
        if len(evidence.matched_patterns) == 1 and matchers == {"filename"}:
            return score * 0.65
        if len(evidence.matched_patterns) == 1:
            pattern = evidence.matched_patterns[0]
            if is_weak_pattern(pattern.matcher, pattern.pattern):
                return score * 0.45
        if len(evidence.matched_patterns) >= 2:
            return min(100.0, score * 1.05)
        return score
