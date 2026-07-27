"""Rule validation utilities."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from techspecter.exceptions import RuleValidationError
from techspecter.analysis.models.finding import Severity
from techspecter.rules.models import Rule, RuleType


@dataclass(slots=True)
class RuleValidationReport:
    """Validation results for a rule collection."""

    is_valid: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class RuleValidator:
    """Validate rule definitions."""

    def validate(self, rules: list[Rule]) -> RuleValidationReport:
        """Validate a collection of rules."""
        report = RuleValidationReport()
        seen_ids: set[str] = set()

        for rule in rules:
            if rule.id in seen_ids:
                report.errors.append(f"Duplicate rule ID '{rule.id}'.")
            seen_ids.add(rule.id)

            if rule.severity.value not in {item.value for item in Severity}:
                report.errors.append(f"Rule '{rule.id}' has invalid severity.")

            if rule.confidence < 0 or rule.confidence > 100:
                report.errors.append(f"Rule '{rule.id}' confidence must be 0–100.")

            if not rule.name.strip() or not rule.description.strip() or not rule.pattern.strip():
                report.errors.append(f"Rule '{rule.id}' is missing required fields.")

            if rule.type == RuleType.REGEX:
                self._validate_regex(rule, report)
            elif rule.type == RuleType.HEADER and rule.pattern.startswith("regex:"):
                self._validate_regex_pattern(rule.id, rule.pattern.removeprefix("regex:"), report)

        report.is_valid = not report.errors
        return report

    def validate_or_raise(self, rules: list[Rule]) -> RuleValidationReport:
        """Validate rules and raise when invalid."""
        report = self.validate(rules)
        if not report.is_valid:
            msg = "; ".join(report.errors)
            raise RuleValidationError(msg)
        return report

    def _validate_regex(self, rule: Rule, report: RuleValidationReport) -> None:
        """Validate regex rule patterns."""
        self._validate_regex_pattern(rule.id, rule.pattern, report)

    def _validate_regex_pattern(
        self,
        rule_id: str,
        pattern: str,
        report: RuleValidationReport,
    ) -> None:
        """Validate a regex pattern compiles."""
        try:
            re.compile(pattern)
        except re.error as exc:
            report.errors.append(f"Rule '{rule_id}' has malformed regex: {exc}")
