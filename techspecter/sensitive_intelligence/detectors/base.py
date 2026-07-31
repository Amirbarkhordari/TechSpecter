"""Base detector interfaces and helpers."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass

from techspecter.sensitive_intelligence.models import (
    ConfidenceLevel,
    FindingType,
    SeverityLevel,
)


@dataclass(frozen=True, slots=True)
class DetectorMatch:
    """Raw match produced by a detector before deduplication."""

    finding_type: FindingType
    subtype: str
    matched_value: str
    matched_pattern: str
    confidence: float
    severity: SeverityLevel
    evidence: str | None = None
    line_number: int | None = None
    byte_offset: int | None = None


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
