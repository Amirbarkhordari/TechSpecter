"""Source map reference pattern matcher."""

from __future__ import annotations

from techspecter.fingerprints.context import MatchContext
from techspecter.fingerprints.matchers.base import PatternMatcher
from techspecter.fingerprints.models import Pattern


class SourceMapMatcher(PatternMatcher):
    """Match patterns against detected source map URLs."""

    matcher_type = "sourcemap"

    def matches(self, pattern: Pattern, context: MatchContext) -> bool:
        """Return whether the source map URL contains the pattern value.

        Args:
            pattern: Fingerprint pattern definition.
            context: JavaScript resource context.

        Returns:
            ``True`` when a source map URL is present and matches the pattern.
        """
        if not context.source_map_url:
            return False
        return pattern.pattern.lower() in context.source_map_url.lower()
