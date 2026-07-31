"""Sensitive data and secrets intelligence models."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import Field

from techspecter.models.base import TechSpecterModel


class FindingType(StrEnum):
    """Top-level finding category."""

    EMAIL = "email"
    PHONE = "phone"
    USERNAME = "username"
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    UUID = "uuid"
    SECRET = "secret"
    CREDENTIAL = "credential"
    COMMENT = "comment"
    HOSTNAME = "hostname"
    ENVIRONMENT = "environment"
    APPLICATION = "application"


class SeverityLevel(StrEnum):
    """Passive severity classification."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ConfidenceLevel(StrEnum):
    """Human-readable confidence band."""

    VERY_HIGH = "very_high"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingLocation(TechSpecterModel):
    """Location of a finding within a source asset."""

    source_file: str | None = None
    source_url: str | None = None
    asset_id: str | None = None
    line_number: int | None = Field(default=None, ge=1)
    byte_offset: int | None = Field(default=None, ge=0)


class SensitiveFindingRecord(TechSpecterModel):
    """A deduplicated sensitive data or secret finding."""

    finding_id: str
    finding_type: FindingType
    subtype: str
    severity: SeverityLevel
    confidence: float = Field(ge=0.0, le=100.0)
    confidence_level: ConfidenceLevel
    matched_value: str
    matched_pattern: str
    detector_name: str
    evidence: str | None = None
    locations: list[FindingLocation] = Field(default_factory=list)
    source_files: list[str] = Field(default_factory=list)
    occurrence_count: int = 1
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SensitiveIntelligenceSummary(TechSpecterModel):
    """Aggregated counts for reporting."""

    emails: int = 0
    phones: int = 0
    secrets: int = 0
    credentials: int = 0
    urls: int = 0
    domains: int = 0
    ips: int = 0
    uuids: int = 0
    comments: int = 0
    other: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0
    total_findings: int = 0
    assets_analyzed: int = 0


class SensitiveIntelligenceReport(TechSpecterModel):
    """Complete sensitive data intelligence output."""

    target_url: str
    findings: list[SensitiveFindingRecord] = Field(default_factory=list)
    summary: SensitiveIntelligenceSummary = Field(default_factory=SensitiveIntelligenceSummary)
    elapsed_ms: float = 0.0
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
