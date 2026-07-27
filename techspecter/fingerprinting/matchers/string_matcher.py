"""Literal string pattern matcher."""

from __future__ import annotations

from techspecter.fingerprinting.context import MatchContext
from techspecter.fingerprinting.matchers.base import PatternMatcher
from techspecter.fingerprinting.models import FingerprintPattern


class StringMatcher(PatternMatcher):
    """Match patterns using case-sensitive substring search."""

    matcher_type = "string"

    def matches(self, pattern: FingerprintPattern, context: MatchContext) -> bool:
        """Return whether the pattern appears in the JavaScript content.

        Args:
            pattern: Fingerprint pattern definition.
            context: JavaScript resource context.

        Returns:
            ``True`` when the literal pattern is found in the content.
        """
        return pattern.pattern in context.content
