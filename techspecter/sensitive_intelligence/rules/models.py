"""Rule engine models for sensitive intelligence detection."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from techspecter.sensitive_intelligence.models import FindingType, SeverityLevel

RuleValidator = Callable[[str, re.Match[str]], bool]


class RuleCategory(StrEnum):
    """High-level detection category for Phase 8 reporting."""

    SECRETS = "secrets"
    CREDENTIALS = "credentials"
    SENSITIVE_CONFIGURATION = "sensitive_configuration"
    DEVELOPER_ARTIFACTS = "developer_artifacts"


@dataclass(frozen=True, slots=True)
class DetectionRule:
    """Declarative detection rule with metadata."""

    rule_id: str
    name: str
    category: RuleCategory
    finding_type: FindingType
    subtype: str
    pattern: re.Pattern[str]
    severity: SeverityLevel
    confidence: float
    description: str
    recommendation: str
    redact: bool = False
    validator: RuleValidator | None = None
