"""Rule engine models."""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field, field_validator

from techspecter.analysis.models.finding import Severity
from techspecter.models.base import TechSpecterModel


class RuleType(StrEnum):
    """Supported rule matcher types."""

    REGEX = "regex"
    STRING = "string"
    HEADER = "header"


class RuleCategory(StrEnum):
    """Standard rule categories."""

    TECHNOLOGY = "Technology"
    HTTP = "HTTP"
    HEADERS = "Headers"
    COOKIES = "Cookies"
    METADATA = "Metadata"
    ENDPOINTS = "Endpoints"
    SENSITIVE_ARTIFACTS = "Sensitive Artifacts"
    CONFIGURATION = "Configuration"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    INFRASTRUCTURE = "Infrastructure"
    CUSTOM = "Custom"


class RuleCondition(TechSpecterModel):
    """Optional conditional logic for rule execution."""

    field: str | None = None
    operator: str | None = None
    value: str | None = None


class Rule(TechSpecterModel):
    """Passive analysis rule definition."""

    id: str
    name: str
    description: str
    category: RuleCategory | str
    severity: Severity = Severity.INFO
    confidence: float = Field(default=50.0, ge=0.0, le=100.0)
    enabled: bool = True
    author: str | None = None
    version: str = "1.0.0"
    tags: list[str] = Field(default_factory=list)
    type: RuleType
    pattern: str
    target: str = "content"
    condition: RuleCondition | None = None
    recommendation: str | None = None
    references: list[str] = Field(default_factory=list)
    flags: str | None = None

    @field_validator("id", "name", "description", "pattern")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        """Ensure required string fields are not blank."""
        if not value.strip():
            msg = "Rule fields must not be empty."
            raise ValueError(msg)
        return value.strip()
