"""Pydantic models for scan reports and export results."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import Field

from techspecter.models.base import TechSpecterModel

ReportFormat = Literal["json", "markdown", "html", "csv", "sarif", "console"]


class ReportTarget(TechSpecterModel):
    """Scan target metadata included in a report."""

    url: str


class ReportEvidence(TechSpecterModel):
    """Evidence supporting a technology detection."""

    matched_file: str | None = None
    matched_pattern: str
    matcher_type: str
    version: str
    confidence: float = Field(ge=0.0, le=100.0)


class ReportTechnology(TechSpecterModel):
    """Detected technology entry in a report."""

    id: str
    name: str
    category: str
    version: str
    confidence: float = Field(ge=0.0, le=100.0)
    source_file: str | None = None
    website: str | None = None
    description: str | None = None
    evidence: list[ReportEvidence] = Field(default_factory=list)


class TechnologyGroup(TechSpecterModel):
    """Technologies grouped by category."""

    category: str
    technologies: list[ReportTechnology] = Field(default_factory=list)


class ReportStatistics(TechSpecterModel):
    """Aggregated statistics for a scan report."""

    total_technologies: int = 0
    category_counts: dict[str, int] = Field(default_factory=dict)
    category_count: int = 0
    average_confidence: float = 0.0
    highest_confidence: float = 0.0
    known_versions: int = 0
    unknown_versions: int = 0
    scripts_analyzed: int = 0


class ReportSummary(TechSpecterModel):
    """High-level report summary."""

    headline: str
    technologies_detected: int = 0
    categories_detected: int = 0


class ReportMetadata(TechSpecterModel):
    """Report metadata and scan context."""

    tool_name: str = "TechSpecter"
    tool_version: str
    scan_timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    target_url: str
    scan_duration_ms: float = 0.0
    scripts_analyzed: int = 0
    technologies_detected: int = 0
    categories_detected: int = 0


class Report(TechSpecterModel):
    """Complete scan report produced by the reporting engine."""

    metadata: ReportMetadata
    target: ReportTarget
    summary: ReportSummary
    statistics: ReportStatistics
    technologies: list[ReportTechnology] = Field(default_factory=list)
    groups: list[TechnologyGroup] = Field(default_factory=list)


class ExportResult(TechSpecterModel):
    """Result of exporting a report to a specific format."""

    format: ReportFormat
    content: str
    output_path: str | None = None
    byte_size: int = 0
