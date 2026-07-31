"""Rule-based sensitive intelligence scanning engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from techspecter.sensitive_intelligence.detectors.base import BaseSensitiveDetector, DetectorMatch
from techspecter.sensitive_intelligence.models import FindingCategory, FindingType
from techspecter.sensitive_intelligence.rules.catalog import builtin_rules
from techspecter.sensitive_intelligence.rules.models import DetectionRule, RuleCategory


@dataclass(slots=True)
class RuleEngine:
    """Execute declarative detection rules against textual content."""

    rules: tuple[DetectionRule, ...] = field(default_factory=builtin_rules)

    def register(self, rule: DetectionRule) -> None:
        """Register an additional rule without modifying core engine code."""
        self.rules = self.rules + (rule,)

    def scan(self, content: str) -> list[DetectorMatch]:
        """Scan content with all registered rules."""
        matches: list[DetectorMatch] = []
        for rule in self.rules:
            matches.extend(self._apply_rule(content, rule))
        return matches

    def scan_category(self, content: str, category: RuleCategory) -> list[DetectorMatch]:
        """Scan content with rules from a single category."""
        return [
            match
            for rule in self.rules
            if rule.category == category
            for match in self._apply_rule(content, rule)
        ]

    def _apply_rule(self, content: str, rule: DetectionRule) -> list[DetectorMatch]:
        results: list[DetectorMatch] = []
        for match in rule.pattern.finditer(content):
            raw = match.group(0)
            if rule.validator is not None and not rule.validator(raw, match):
                continue
            start = match.start()
            line = content.count("\n", 0, start) + 1
            line_start = content.rfind("\n", 0, start) + 1
            column = start - line_start + 1
            snippet_start = max(0, start - 40)
            snippet_end = min(len(content), match.end() + 40)
            confidence = rule.confidence
            if rule.validator is not None:
                confidence = min(100.0, confidence + 3.0)
            value = (
                f"{rule.subtype} [redacted]"
                if rule.redact
                else raw[:120] + ("..." if len(raw) > 120 else "")
            )
            results.append(
                DetectorMatch(
                    finding_type=rule.finding_type,
                    subtype=rule.subtype,
                    matched_value=value,
                    matched_pattern=rule.pattern.pattern,
                    confidence=confidence,
                    severity=rule.severity,
                    evidence=content[snippet_start:snippet_end],
                    line_number=line,
                    byte_offset=start,
                    column_number=column,
                    category=FindingCategory(rule.category.value),
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    description=rule.description,
                    recommendation=rule.recommendation,
                ),
            )
        return results


@dataclass(slots=True)
class RuleEngineDetector(BaseSensitiveDetector):
    """Detector adapter that delegates to the rule engine."""

    detector_id: str
    finding_type: FindingType
    category: RuleCategory
    engine: RuleEngine = field(default_factory=RuleEngine)

    def detect(self, content: str) -> list[DetectorMatch]:
        """Run rule engine scans for the configured category."""
        return self.engine.scan_category(content, self.category)
