"""Source map reference pattern matcher."""

from __future__ import annotations

import re

from techspecter.fingerprinting.context import MatchContext
from techspecter.fingerprinting.matchers.base import PatternMatcher
from techspecter.fingerprinting.models import FingerprintPattern


class SourceMapMatcher(PatternMatcher):
    """Match patterns against detected source map URLs and map references."""

    matcher_type = "sourcemap"

    def __init__(self) -> None:
        """Initialize regex cache for source map analysis."""
        self._regex_cache: dict[str, re.Pattern[str]] = {}

    def matches(self, pattern: FingerprintPattern, context: MatchContext) -> bool:
        """Return whether the source map URL or inline reference matches."""
        haystacks: list[str] = []
        if context.source_map_url:
            haystacks.append(context.source_map_url)
        if "sourceMappingURL=" in context.content:
            haystacks.append(context.content)

        if not haystacks:
            return False

        value = pattern.pattern.lower()
        if value.startswith("re:"):
            compiled = self._compile_regex(value[3:])
            return any(compiled.search(item) for item in haystacks)

        return any(value in item.lower() for item in haystacks)

    def _compile_regex(self, expression: str) -> re.Pattern[str]:
        """Compile and cache a source map regex pattern."""
        cached = self._regex_cache.get(expression)
        if cached is not None:
            return cached
        compiled = re.compile(expression, re.IGNORECASE)
        self._regex_cache[expression] = compiled
        return compiled
