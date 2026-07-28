"""Rule execution engine."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from techspecter.analysis.models.evidence import Evidence
from techspecter.analysis.models.finding import Finding
from techspecter.rules.context import RuleExecutionContext
from techspecter.rules.executors.base import RuleExecutor
from techspecter.rules.executors.header import HeaderRuleExecutor
from techspecter.rules.executors.regex import RegexRuleExecutor
from techspecter.rules.executors.string import StringRuleExecutor
from techspecter.rules.loader import RuleLoader
from techspecter.rules.models import Rule
from techspecter.rules.shared import create_rule_loader, get_shared_regex_cache
from techspecter.rules.validator import RuleValidator

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class RuleRunResult:
    """Result produced by the rule runner."""

    findings: list[Finding] = field(default_factory=list)
    rules_executed: int = 0
    rules_matched: int = 0
    elapsed_ms: float = 0.0
    executed_rule_ids: list[str] = field(default_factory=list)


class RuleRunner:
    """Execute passive analysis rules and produce findings."""

    def __init__(
        self,
        *,
        loader: RuleLoader | None = None,
        validator: RuleValidator | None = None,
        executors: list[RuleExecutor] | None = None,
        min_confidence: float = 0.0,
    ) -> None:
        """Initialize the rule runner."""
        regex_cache = get_shared_regex_cache()
        self._loader = loader or create_rule_loader()
        self._validator = validator or RuleValidator()
        self._executors = executors or [
            RegexRuleExecutor(regex_cache=regex_cache),
            StringRuleExecutor(),
            HeaderRuleExecutor(regex_cache=regex_cache),
        ]
        self._min_confidence = min_confidence
        self._executor_map = {executor.rule_type: executor for executor in self._executors}

    def run(
        self,
        context: RuleExecutionContext,
        *,
        rules: list[Rule] | None = None,
    ) -> RuleRunResult:
        """Execute all enabled rules against the provided context."""
        started = time.perf_counter()
        loaded_rules = rules if rules is not None else self._loader.load_all()
        if rules is None:
            self._validator.validate_or_raise(loaded_rules)

        findings: list[Finding] = []
        executed_ids: set[str] = set()
        matched = 0

        for rule in loaded_rules:
            if not rule.enabled:
                continue
            if rule.id in executed_ids:
                continue
            if rule.confidence < self._min_confidence:
                continue

            executor = self._executor_map.get(rule.type.value)
            if executor is None:
                logger.debug("No executor for rule type '%s'", rule.type.value)
                continue

            executed_ids.add(rule.id)
            match = executor.execute(rule, context)
            if match is None:
                continue

            matched += 1
            findings.append(_rule_match_to_finding(match))

        elapsed_ms = (time.perf_counter() - started) * 1000
        logger.info(
            "Rule runner matched %d/%d rules in %.2f ms",
            matched,
            len(executed_ids),
            elapsed_ms,
        )
        return RuleRunResult(
            findings=findings,
            rules_executed=len(executed_ids),
            rules_matched=matched,
            elapsed_ms=elapsed_ms,
            executed_rule_ids=sorted(executed_ids),
        )


def _rule_match_to_finding(match: object) -> Finding:
    """Convert a rule match into a standardized finding."""
    from techspecter.rules.executors.base import RuleMatch

    assert isinstance(match, RuleMatch)
    rule = match.rule
    return Finding(
        id=f"rule:{rule.id}",
        analyzer="rule-engine",
        category=rule.category,
        title=rule.name,
        description=rule.description,
        severity=rule.severity,
        confidence=rule.confidence,
        evidence=[
            Evidence(
                url=match.location,
                file=match.location,
                snippet=match.snippet,
            )
        ],
        location=match.location,
        recommendation=rule.recommendation,
        metadata={
            "rule_id": rule.id,
            "rule_type": rule.type.value,
            "rule_version": rule.version,
            "tags": rule.tags,
            "references": rule.references,
            "matched_value": match.matched_value,
        },
    )
