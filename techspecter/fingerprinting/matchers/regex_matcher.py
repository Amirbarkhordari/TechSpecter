"""Regular expression pattern matcher."""

from __future__ import annotations

import re

from techspecter.exceptions import PatternMatchError
from techspecter.fingerprinting.context import MatchContext
from techspecter.fingerprinting.matchers.base import PatternMatcher
from techspecter.fingerprinting.models import FingerprintPattern


class RegexMatcher(PatternMatcher):
    """Match patterns using compiled regular expressions."""

    matcher_type = "regex"

    def __init__(self) -> None:
        """Initialize an empty regex compilation cache."""
        self._cache: dict[tuple[str, str | None], re.Pattern[str]] = {}

    def matches(self, pattern: FingerprintPattern, context: MatchContext) -> bool:
        """Return whether the regex matches the JavaScript content.

        Args:
            pattern: Fingerprint pattern definition.
            context: JavaScript resource context.

        Returns:
            ``True`` when the regular expression matches the content.
        """
        try:
            compiled = self._compile(pattern.pattern, pattern.flags)
        except re.error as exc:
            raise PatternMatchError(str(exc)) from exc
        return compiled.search(context.content) is not None

    def _compile(self, expression: str, flags: str | None) -> re.Pattern[str]:
        """Compile and cache a regular expression.

        Args:
            expression: Regular expression source.
            flags: Optional flag string.

        Returns:
            Compiled regular expression.
        """
        cache_key = (expression, flags)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        flag_value = 0
        if flags:
            for flag in flags:
                if flag == "i":
                    flag_value |= re.IGNORECASE
                elif flag == "m":
                    flag_value |= re.MULTILINE
                elif flag == "s":
                    flag_value |= re.DOTALL

        compiled = re.compile(expression, flag_value)
        self._cache[cache_key] = compiled
        return compiled
