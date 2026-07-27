"""Global variable pattern matcher."""

from __future__ import annotations

import re

from techspecter.fingerprinting.context import MatchContext
from techspecter.fingerprinting.matchers.base import PatternMatcher
from techspecter.fingerprinting.models import FingerprintPattern

_BOOTSTRAP_MARKERS = (
    "__webpack_require__",
    "__vite__",
    "webpackJsonp",
    "__NEXT_DATA__",
    "__NUXT__",
)


class GlobalVariableMatcher(PatternMatcher):
    """Match JavaScript global variable declarations, references, and bootstrap markers."""

    matcher_type = "global"

    def __init__(self) -> None:
        """Initialize an empty global matcher regex cache."""
        self._cache: dict[str, re.Pattern[str]] = {}

    def matches(self, pattern: FingerprintPattern, context: MatchContext) -> bool:
        """Return whether the global variable appears in the JavaScript content."""
        if pattern.pattern in _BOOTSTRAP_MARKERS and pattern.pattern in context.content:
            return True

        compiled = self._global_pattern(pattern.pattern)
        if compiled.search(context.content) is not None:
            return True

        return self._matches_runtime_bootstrap(pattern.pattern, context.content)

    def _matches_runtime_bootstrap(self, name: str, content: str) -> bool:
        """Detect runtime bootstrap patterns for common bundlers and frameworks."""
        if name == "webpackBootstrap":
            return "__webpack_require__" in content or "webpackJsonp" in content
        if name == "viteBootstrap":
            return "__vite__" in content or "import.meta.hot" in content
        return False

    def _global_pattern(self, name: str) -> re.Pattern[str]:
        """Build or retrieve a cached regex for a global variable name."""
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
