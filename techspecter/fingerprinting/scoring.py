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
    version_pattern: None | VersionPattern = None


@dataclass(slots=True)
class ConfidenceScorer:
    """Calculate normalized confidence scores for technology matches."""

    min_confidence: float = 45.0
    matcher_multipliers: dict[str, float] = field(default_factory=lambda: dict(MATCHER_MULTIPLIERS))

    def score(self, fingerprint: Fingerprint, evidence: MatchEvidence, version: str) -> float:
        """Calculate a confidence score from matched evidence strength."""
        matched_weight = sum(
            self._weighted_pattern_score(pattern) for pattern in evidence.matched_patterns
        )
        if matched_weight <= 0:
            return 0.0

        # Score from matched evidence only — not diluted by unmatched signature patterns.
        score = min(100.0, matched_weight * 1.15)

        if evidence.version_pattern is not None and version != UNKNOWN_VERSION:
            score = min(100.0, score + min(20.0, evidence.version_pattern.weight * 0.6))

        if len(evidence.matched_patterns) >= 2:
            score = min(100.0, score * 1.08)

        adjusted = self._apply_match_quality_rules(score, evidence)
        blended = (adjusted * 0.82) + (fingerprint.confidence * 0.18)
        return round(min(100.0, max(0.0, blended)), 2)

    def passes_threshold(self, confidence: float) -> bool:
        """Return whether a confidence score meets the minimum threshold."""
        return confidence >= self.min_confidence

    def _weighted_pattern_score(self, pattern: FingerprintPattern) -> float:
        """Apply matcher-type multiplier to a pattern weight."""
        multiplier = self.matcher_multipliers.get(pattern.matcher, 1.0)
        return pattern.weight * multiplier

    def _apply_match_quality_rules(self, score: float, evidence: MatchEvidence) -> float:
        """Adjust score based on match quality heuristics."""
        from techspecter.fingerprinting.match_quality import is_strong_pattern, is_weak_pattern

        strong_count = sum(
            1
            for pattern in evidence.matched_patterns
            if is_strong_pattern(pattern.matcher, pattern.pattern)
        )
        if strong_count >= 2:
            return min(100.0, score * 1.12)
        if strong_count == 1:
            return min(100.0, score * 1.08)

        matchers = {pattern.matcher for pattern in evidence.matched_patterns}
        if len(evidence.matched_patterns) == 1 and matchers == {"filename"}:
            return score * 0.65
        if len(evidence.matched_patterns) == 1:
            pattern = evidence.matched_patterns[0]
            if is_weak_pattern(pattern.matcher, pattern.pattern):
                return score * 0.4
        return score
