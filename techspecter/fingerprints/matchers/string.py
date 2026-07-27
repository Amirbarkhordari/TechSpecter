"""Literal string pattern matcher."""

from __future__ import annotations

from techspecter.fingerprints.context import MatchContext
from techspecter.fingerprints.matchers.base import PatternMatcher
from techspecter.fingerprints.models import Pattern


class StringMatcher(PatternMatcher):
    """Match patterns using case-sensitive substring search."""

    matcher_type = "string"

    def matches(self, pattern: Pattern, context: MatchContext) -> bool:
        """Return whether the pattern appears in the JavaScript content.

        Args:
            pattern: Fingerprint pattern definition.
            context: JavaScript resource context.

        Returns:
            ``True`` when the literal pattern is found in the content.
        """
        return pattern.pattern in context.content
