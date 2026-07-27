"""Rule engine caching utilities."""

from __future__ import annotations

import re
from functools import lru_cache


class RegexCache:
    """Cache compiled regular expressions."""

    def __init__(self, *, maxsize: int = 512) -> None:
        """Initialize the regex cache."""
        self._maxsize = maxsize

    @lru_cache(maxsize=512)
    def compile(self, pattern: str, flags: int = 0) -> re.Pattern[str]:
        """Compile and cache a regular expression."""
        return re.compile(pattern, flags)

    def clear(self) -> None:
        """Clear the regex cache."""
        self.compile.cache_clear()


class RuleCache:
    """Cache loaded rule collections."""

    def __init__(self) -> None:
        """Initialize an empty rule cache."""
        self._rules: dict[str, list] = {}

    def get(self, cache_key: str) -> list | None:
        """Return cached rules for a key."""
        return self._rules.get(cache_key)

    def set(self, cache_key: str, rules: list) -> None:
        """Store rules in the cache."""
        self._rules[cache_key] = rules

    def clear(self) -> None:
        """Clear all cached rules."""
        self._rules.clear()
