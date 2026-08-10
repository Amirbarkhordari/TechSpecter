"""Base detector interfaces and helpers."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass

from techspecter.sensitive_intelligence.models import (
    ConfidenceLevel,
    FindingCategory,
    FindingType,
    SeverityLevel,
)


@dataclass(frozen=True, slots=True)
class DetectorMatch:
    """Raw match produced by a detector before candidate validation."""

    finding_type: FindingType
    subtype: str
    matched_value: str
    matched_pattern: str
    confidence: float
    severity: SeverityLevel
    evidence: str | None = None
    line_number: int | None = None
    byte_offset: int | None = None
    column_number: int | None = None
    category: FindingCategory | None = None
    rule_id: str | None = None
    rule_name: str | None = None
    description: str | None = None
    recommendation: str | None = None
    raw_value: str | None = None


class BaseSensitiveDetector(ABC):
    """Pluggable passive sensitive data detector."""

    detector_id: str
    finding_type: FindingType

    @abstractmethod
    def detect(self, content: str) -> list[DetectorMatch]:
        """Scan content and return raw matches."""

    def _scan_patterns(
        self,
        content: str,
        patterns: tuple[tuple[str, re.Pattern[str], float, SeverityLevel], ...],
        *,
        finding_type: FindingType | None = None,
        redact: bool = False,
    ) -> list[DetectorMatch]:
        """Run regex patterns and compute line/offset metadata."""
        matches: list[DetectorMatch] = []
        ftype = finding_type or self.finding_type
        for subtype, pattern, confidence, severity in patterns:
            for match in pattern.finditer(content):
                raw = match.group(0)
                value = self._redact_value(subtype, raw) if redact else raw
                start = match.start()
                line = content.count("\n", 0, start) + 1
                snippet_start = max(0, start - 30)
                snippet_end = min(len(content), match.end() + 30)
                line_start = content.rfind("\n", 0, start) + 1
                matches.append(
                    DetectorMatch(
                        finding_type=ftype,
                        subtype=subtype,
                        matched_value=value,
                        matched_pattern=pattern.pattern,
                        confidence=confidence,
                        severity=severity,
                        evidence=content[snippet_start:snippet_end],
                        line_number=line,
                        byte_offset=start,
                        column_number=start - line_start + 1,
                        category=_category_for_finding_type(ftype),
                        raw_value=raw,
                    ),
                )
        return matches

    @staticmethod
    def _redact_value(subtype: str, value: str) -> str:
        secret_types = {
            "aws-access-key",
            "google-api-key",
            "github-token",
            "gitlab-token",
            "stripe-secret-key",
            "jwt-token",
            "bearer-token",
            "openai-key",
            "anthropic-key",
            "slack-token",
            "discord-token",
            "private-key",
            "pem-block",
        }
        if subtype in secret_types or len(value) > 40:
            return f"{subtype} [redacted]"
        return value[:120] + ("..." if len(value) > 120 else "")

    @staticmethod
    def confidence_level(score: float) -> ConfidenceLevel:
        """Map numeric confidence to a level."""
        if score >= 95:
            return ConfidenceLevel.VERY_HIGH
        if score >= 80:
            return ConfidenceLevel.HIGH
        if score >= 60:
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.LOW


def _category_for_finding_type(finding_type: FindingType) -> FindingCategory:
    if finding_type in {FindingType.EMAIL, FindingType.PHONE, FindingType.USERNAME}:
        return FindingCategory.CONTACT_INFORMATION
    if finding_type == FindingType.SECRET:
        return FindingCategory.SECRETS
    if finding_type == FindingType.CREDENTIAL:
        return FindingCategory.CREDENTIALS
    if finding_type == FindingType.SENSITIVE_CONFIG:
        return FindingCategory.SENSITIVE_CONFIGURATION
    if finding_type == FindingType.COMMENT:
        return FindingCategory.DEVELOPER_ARTIFACTS
    return FindingCategory.OTHER


def resolve_finding_category(match: DetectorMatch) -> FindingCategory:
    """Resolve reporting category from rule metadata or finding type."""
    if isinstance(match.category, FindingCategory):
        return match.category
    return _category_for_finding_type(match.finding_type)
