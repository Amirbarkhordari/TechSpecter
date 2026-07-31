"""Extensible rule-based sensitive intelligence detection."""

from techspecter.sensitive_intelligence.rules.catalog import builtin_rules
from techspecter.sensitive_intelligence.rules.engine import RuleEngine
from techspecter.sensitive_intelligence.rules.models import DetectionRule, RuleCategory

__all__ = [
    "DetectionRule",
    "RuleCategory",
    "RuleEngine",
    "builtin_rules",
]
