"""Filename-based pattern matcher."""

from __future__ import annotations

import re

from techspecter.fingerprinting.context import MatchContext
from techspecter.fingerprinting.matchers.base import PatternMatcher
from techspecter.fingerprinting.models import FingerprintPattern

_CHUNK_HINTS = (".chunk.", "-chunk-", ".vendor.", "-vendor-", ".bundle.", "-bundle-")


class FilenameMatcher(PatternMatcher):
    """Match patterns against filenames, URLs, and bundle naming conventions."""

    matcher_type = "filename"

    def __init__(self) -> None:
        """Initialize regex cache for filename heuristics."""
        self._regex_cache: dict[str, re.Pattern[str]] = {}

    def matches(self, pattern: FingerprintPattern, context: MatchContext) -> bool:
        """Return whether the filename or URL path matches the pattern."""
        targets = (
            context.filename.lower(),
            context.url.lower(),
        )
        value = pattern.pattern.lower()

        if value.startswith("re:"):
            compiled = self._compile_regex(value[3:])
            return any(compiled.search(target) for target in targets)

        if any(value in target for target in targets):
            return True

        return self._matches_bundle_heuristic(value, targets)

    def _matches_bundle_heuristic(self, value: str, targets: tuple[str, ...]) -> bool:
        """Detect common webpack/vite chunk and vendor naming conventions."""
        if value not in {"chunk", "vendor", "bundle"}:
            return False
        if value == "chunk":
            return any("webpack" in target for target in targets)
        return any(any(hint in target for hint in _CHUNK_HINTS) for target in targets)

    def _compile_regex(self, expression: str) -> re.Pattern[str]:
        """Compile and cache a filename regex pattern."""
        cached = self._regex_cache.get(expression)
        if cached is not None:
            return cached
        compiled = re.compile(expression, re.IGNORECASE)
        self._regex_cache[expression] = compiled
        return compiled
