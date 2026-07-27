"""Header rule executor."""

from __future__ import annotations

import re

from techspecter.rules.cache import RegexCache
from techspecter.rules.context import RuleExecutionContext
from techspecter.rules.executors.base import RuleExecutor, RuleMatch
from techspecter.rules.models import Rule, RuleType


class HeaderRuleExecutor(RuleExecutor):
    """Execute header rules against response headers."""

    rule_type = RuleType.HEADER.value

    def __init__(self, *, regex_cache: RegexCache | None = None) -> None:
        """Initialize the header executor."""
        self._cache = regex_cache or RegexCache()

    def execute(self, rule: Rule, context: RuleExecutionContext) -> RuleMatch | None:
        """Match a header name or name:value pattern."""
        if not context.headers:
            return None

        pattern = rule.pattern
        for name, value in context.header_items():
            candidate = f"{name}: {value}" if rule.target != "header_name" else name
            haystack = name if rule.target == "header_name" else candidate

            if _matches_header_pattern(pattern, haystack, self._cache, rule.flags):
                return RuleMatch(
                    rule=rule,
                    matched_value=candidate,
                    location=context.target_url,
                    snippet=candidate[:500],
                )
        return None


def _matches_header_pattern(
    pattern: str,
    haystack: str,
    cache: RegexCache,
    flags: str | None,
) -> bool:
    """Return whether a header value matches a string or regex pattern."""
    if pattern.startswith("regex:"):
        compiled = cache.compile(pattern.removeprefix("regex:"), _parse_header_flags(flags))
        return compiled.search(haystack) is not None
    return pattern.lower() in haystack.lower()


def _parse_header_flags(raw: str | None) -> int:
    """Parse regex flags for header matching."""
    if not raw:
        return re.IGNORECASE
    flags = 0
    mapping = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}
    for char in raw:
        flags |= mapping.get(char.lower(), 0)
    return flags or re.IGNORECASE
