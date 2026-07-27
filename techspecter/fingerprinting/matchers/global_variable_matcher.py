"""Global variable pattern matcher."""

from __future__ import annotations

import re

from techspecter.fingerprinting.context import MatchContext
from techspecter.fingerprinting.matchers.base import PatternMatcher
from techspecter.fingerprinting.models import FingerprintPattern


class GlobalVariableMatcher(PatternMatcher):
    """Match JavaScript global variable declarations and references."""

    matcher_type = "global"

    def __init__(self) -> None:
        """Initialize an empty global matcher regex cache."""
        self._cache: dict[str, re.Pattern[str]] = {}

    def matches(self, pattern: FingerprintPattern, context: MatchContext) -> bool:
        """Return whether the global variable appears in the JavaScript content.

        Args:
            pattern: Fingerprint pattern definition.
            context: JavaScript resource context.

        Returns:
            ``True`` when a global variable reference is detected.
        """
        compiled = self._global_pattern(pattern.pattern)
        return compiled.search(context.content) is not None

    def _global_pattern(self, name: str) -> re.Pattern[str]:
        """Build or retrieve a cached regex for a global variable name.

        Args:
            name: Global variable identifier.

        Returns:
            Compiled regular expression.
        """
        cached = self._cache.get(name)
        if cached is not None:
            return cached

        escaped = re.escape(name)
        expression = (
            rf"(?:\b(?:var|let|const)\s+{escaped}\b|"
            rf"\bwindow\.{escaped}\b|"
            rf"\bself\.{escaped}\b|"
            rf"\bglobalThis\.{escaped}\b|"
            rf"\b{escaped}\s*[.=])"
        )
        compiled = re.compile(expression)
        self._cache[name] = compiled
        return compiled
