"""Rule executor base classes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from techspecter.rules.context import RuleExecutionContext
from techspecter.rules.models import Rule


@dataclass(slots=True)
class RuleMatch:
    """Result of a successful rule match."""

    rule: Rule
    matched_value: str
    location: str | None = None
    snippet: str | None = None


class RuleExecutor(ABC):
    """Base class for rule executors."""

    rule_type: str

    @abstractmethod
    def execute(self, rule: Rule, context: RuleExecutionContext) -> RuleMatch | None:
        """Execute a rule against the provided context."""

    def supports(self, rule: Rule) -> bool:
        """Return whether this executor supports the rule type."""
        return rule.type.value == self.rule_type
