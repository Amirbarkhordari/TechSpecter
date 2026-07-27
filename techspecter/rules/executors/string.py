"""String rule executor."""

from __future__ import annotations

from techspecter.rules.context import RuleExecutionContext
from techspecter.rules.executors.base import RuleExecutor, RuleMatch
from techspecter.rules.executors.regex import _resolve_target
from techspecter.rules.models import Rule, RuleType


class StringRuleExecutor(RuleExecutor):
    """Execute substring rules against textual content."""

    rule_type = RuleType.STRING.value

    def execute(self, rule: Rule, context: RuleExecutionContext) -> RuleMatch | None:
        """Search content for a literal substring."""
        haystack = _resolve_target(rule.target, context)
        if not haystack or rule.pattern not in haystack:
            return None

        return RuleMatch(
            rule=rule,
            matched_value=rule.pattern,
            location=context.filename or context.target_url,
            snippet=rule.pattern[:500],
        )
