"""Rule engine caching utilities."""

from __future__ import annotations

import re
from collections import OrderedDict

from techspecter.rules.models import Rule


class RegexCache:
    """Cache compiled regular expressions without instance-method LRU leaks."""

    def __init__(self, *, maxsize: int = 512) -> None:
        """Initialize the regex cache."""
        self._maxsize = maxsize
        self._cache: OrderedDict[tuple[str, int], re.Pattern[str]] = OrderedDict()

    def compile(self, pattern: str, flags: int = 0) -> re.Pattern[str]:
        """Compile and cache a regular expression."""
        key = (pattern, flags)
        cached = self._cache.get(key)
        if cached is not None:
            self._cache.move_to_end(key)
            return cached

        compiled = re.compile(pattern, flags)
        self._cache[key] = compiled
        if len(self._cache) > self._maxsize:
            self._cache.popitem(last=False)
        return compiled

    def clear(self) -> None:
        """Clear the regex cache."""
        self._cache.clear()


class RuleCache:
    """Cache loaded rule collections."""

    def __init__(self) -> None:
        """Initialize an empty rule cache."""
        self._rules: dict[str, list[Rule]] = {}

    def get(self, cache_key: str) -> list[Rule] | None:
        """Return cached rules for a key."""
        return self._rules.get(cache_key)

    def set(self, cache_key: str, rules: list[Rule]) -> None:
        """Store rules in the cache."""
        self._rules[cache_key] = rules

    def clear(self) -> None:
        """Clear all cached rules."""
        self._rules.clear()
