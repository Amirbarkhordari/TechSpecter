"""Source map reference pattern matcher."""

from __future__ import annotations

from techspecter.fingerprinting.context import MatchContext
from techspecter.fingerprinting.matchers.base import PatternMatcher
from techspecter.fingerprinting.models import FingerprintPattern


class SourceMapMatcher(PatternMatcher):
    """Match patterns against detected source map URLs."""

    matcher_type = "sourcemap"

    def matches(self, pattern: FingerprintPattern, context: MatchContext) -> bool:
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
