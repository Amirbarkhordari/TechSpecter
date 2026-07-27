"""Generic finding models for passive web application analysis."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import Field

from techspecter.analysis.models.confidence import normalize_confidence
from techspecter.analysis.models.evidence import Evidence
from techspecter.models.base import TechSpecterModel


class Severity(StrEnum):
    """Finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingCategory(StrEnum):
    """Standard finding categories."""

    TECHNOLOGY = "Technology"
    HTTP = "HTTP"
    HEADERS = "Headers"
    COOKIES = "Cookies"
    METADATA = "Metadata"
    ENDPOINT = "Endpoint"
    SENSITIVE_ARTIFACT = "Sensitive Artifact"
    CONFIGURATION = "Configuration"
    INFRASTRUCTURE = "Infrastructure"
    INFORMATION = "Information"
    CUSTOM = "Custom"


class Finding(TechSpecterModel):
    """A single passive analysis finding produced by an analyzer."""

    id: str
    analyzer: str
    category: FindingCategory | str
    title: str
    description: str
    severity: Severity = Severity.INFO
    confidence: float = Field(default=0.0, ge=0.0, le=100.0)
    evidence: list[Evidence] = Field(default_factory=list)
    location: str | None = None
    recommendation: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    def normalized_confidence(self) -> float:
        """Return the confidence score normalized to 0–100."""
        return normalize_confidence(self.confidence)
