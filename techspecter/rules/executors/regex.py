"""Regex rule executor."""

from __future__ import annotations

import logging
import re

from techspecter.rules.cache import RegexCache
from techspecter.rules.context import RuleExecutionContext
from techspecter.rules.executors.base import RuleExecutor, RuleMatch
from techspecter.rules.models import Rule, RuleType

logger = logging.getLogger(__name__)


class RegexRuleExecutor(RuleExecutor):
    """Execute regex rules against textual content."""

    rule_type = RuleType.REGEX.value

    def __init__(self, *, regex_cache: RegexCache | None = None) -> None:
        """Initialize the regex executor."""
        self._cache = regex_cache or RegexCache()

    def execute(self, rule: Rule, context: RuleExecutionContext) -> RuleMatch | None:
        """Search content using a compiled regular expression."""
        if rule.target not in {"content", "filename", "url"}:
            return None

        haystack = _resolve_target(rule.target, context)
        if not haystack:
            return None

        flags = _parse_flags(rule.flags)
        try:
            compiled = self._cache.compile(rule.pattern, flags)
        except re.error as exc:
            logger.warning("Invalid regex in rule '%s': %s", rule.id, exc)
            return None

        match = compiled.search(haystack)
        if match is None:
            return None

        snippet = match.group(0)
        return RuleMatch(
            rule=rule,
            matched_value=snippet,
            location=context.filename or context.target_url,
            snippet=snippet[:500],
        )


def _resolve_target(target: str, context: RuleExecutionContext) -> str | None:
    """Resolve the target field from the execution context."""
    if target == "content":
        return context.content
    if target == "filename":
        return context.filename
    if target == "url":
        return context.target_url
    return context.content


def _parse_flags(raw: str | None) -> int:
    """Parse regex flag letters into a flag integer."""
    if not raw:
        return 0
    flags = 0
    mapping = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}
    for char in raw:
        flags |= mapping.get(char.lower(), 0)
    return flags
