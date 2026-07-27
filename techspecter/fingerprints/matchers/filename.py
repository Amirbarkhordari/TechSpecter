"""Filename-based pattern matcher."""

from __future__ import annotations

from techspecter.fingerprints.context import MatchContext
from techspecter.fingerprints.matchers.base import PatternMatcher
from techspecter.fingerprints.models import Pattern


class FilenameMatcher(PatternMatcher):
    """Match patterns against the JavaScript resource filename."""

    matcher_type = "filename"

    def matches(self, pattern: Pattern, context: MatchContext) -> bool:
        """Return whether the filename contains the pattern value.

        Args:
            pattern: Fingerprint pattern definition.
            context: JavaScript resource context.

        Returns:
            ``True`` when the filename contains the pattern (case-insensitive).
        """
        return pattern.pattern.lower() in context.filename.lower()
