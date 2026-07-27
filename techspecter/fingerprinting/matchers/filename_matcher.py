"""Filename-based pattern matcher."""

from __future__ import annotations

from techspecter.fingerprinting.context import MatchContext
from techspecter.fingerprinting.matchers.base import PatternMatcher
from techspecter.fingerprinting.models import FingerprintPattern


class FilenameMatcher(PatternMatcher):
    """Match patterns against the JavaScript resource filename."""

    matcher_type = "filename"

    def matches(self, pattern: FingerprintPattern, context: MatchContext) -> bool:
        """Return whether the filename contains the pattern value.

        Args:
            pattern: Fingerprint pattern definition.
            context: JavaScript resource context.

        Returns:
            ``True`` when the filename contains the pattern (case-insensitive).
        """
        return pattern.pattern.lower() in context.filename.lower()
