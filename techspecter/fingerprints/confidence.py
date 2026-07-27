"""Confidence scoring for fingerprint matches."""

from __future__ import annotations

from dataclasses import dataclass

from techspecter.fingerprints.models import UNKNOWN_VERSION, Fingerprint, Pattern, VersionPattern


@dataclass(frozen=True, slots=True)
class MatchEvidence:
    """Evidence collected during fingerprint matching."""

    matched_patterns: list[Pattern]
    version_pattern: VersionPattern | None = None


class ConfidenceScorer:
    """Calculate normalized confidence scores for technology matches."""

    def score(self, fingerprint: Fingerprint, evidence: MatchEvidence, version: str) -> float:
        """Calculate a normalized confidence score from 0 to 100.

        Args:
            fingerprint: Technology fingerprint definition.
            evidence: Matched pattern evidence.
            version: Extracted version string.

        Returns:
            Normalized confidence score.
        """
        earned = sum(pattern.weight for pattern in evidence.matched_patterns)
        max_possible = sum(pattern.weight for pattern in fingerprint.patterns)

        if evidence.version_pattern is not None and version != UNKNOWN_VERSION:
            earned += evidence.version_pattern.weight
            max_possible += sum(item.weight for item in fingerprint.version_patterns)

        if max_possible <= 0:
            return min(100.0, fingerprint.confidence)

        normalized = (earned / max_possible) * 100.0
        blended = (normalized + fingerprint.confidence) / 2.0
        return round(min(100.0, max(0.0, blended)), 2)
