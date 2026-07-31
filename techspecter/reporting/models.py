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
    """Evidence supporting a technology detection or generic finding."""

    matched_file: str | None = None
    matched_pattern: str | None = None
    matcher_type: str | None = None
    version: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=100.0)
    url: str | None = None
    line: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)
    snippet: str | None = None
    header: str | None = None
    cookie: str | None = None
    html_element: str | None = None
    javascript_location: str | None = None


class ReportFinding(TechSpecterModel):
    """Generic finding entry in a report."""

    id: str
    analyzer: str
    category: str
    title: str
    description: str
    severity: str
    confidence: float = Field(ge=0.0, le=100.0)
    location: str | None = None
    recommendation: str | None = None
    evidence: list[ReportEvidence] = Field(default_factory=list)
    metadata: dict[str, object] = Field(default_factory=dict)


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
    version_source: str | None = None
    version_confidence: float | None = Field(default=None, ge=0.0, le=100.0)
    evidence_count: int = 0
    detection_reason: str | None = None
    detected_by: list[str] = Field(default_factory=list)
    detection_methods: list[str] = Field(default_factory=list)
    summary_group: str | None = None
    security_findings_count: int = 0


class TechnologyGroup(TechSpecterModel):
    """Technologies grouped by category."""

    category: str
    technologies: list[ReportTechnology] = Field(default_factory=list)


class ReportStatistics(TechSpecterModel):
    """Aggregated statistics for a scan report."""

    total_technologies: int = 0
    total_findings: int = 0
    category_counts: dict[str, int] = Field(default_factory=dict)
    category_count: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)
    analyzer_counts: dict[str, int] = Field(default_factory=dict)
    average_confidence: float = 0.0
    highest_confidence: float = 0.0
    known_versions: int = 0
    unknown_versions: int = 0
    scripts_analyzed: int = 0


class ReportSummary(TechSpecterModel):
    """High-level report summary."""

    headline: str
    technologies_detected: int = 0
    findings_detected: int = 0
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
    findings_detected: int = 0
    categories_detected: int = 0


class ReportSection(TechSpecterModel):
    """Structured report section for grouped findings and summaries."""

    id: str
    title: str
    summary: str | None = None
    findings: list[ReportFinding] = Field(default_factory=list)
    metadata: dict[str, object] = Field(default_factory=dict)


class ReportAssetEntry(TechSpecterModel):
    """Export-ready asset inventory entry."""

    asset_id: str
    url: str
    filename: str
    extension: str | None = None
    category: str
    content_type: str | None = None
    mime_type: str | None = None
    http_status: int | None = None
    file_size: int | None = None
    sha256: str | None = None
    download_success: bool = False
    referenced_by: str | None = None
    discovery_sources: list[str] = Field(default_factory=list)


class ReportAssetInventory(TechSpecterModel):
    """Export-ready asset inventory for JSON/HTML/SARIF exporters."""

    target_url: str
    summary: dict[str, int]
    total_assets: int = 0
    assets: list[ReportAssetEntry] = Field(default_factory=list)
    elapsed_ms: float = 0.0


class Report(TechSpecterModel):
    """Complete scan report produced by the reporting engine."""

    metadata: ReportMetadata
    target: ReportTarget
    summary: ReportSummary
    statistics: ReportStatistics
    technologies: list[ReportTechnology] = Field(default_factory=list)
    findings: list[ReportFinding] = Field(default_factory=list)
    groups: list[TechnologyGroup] = Field(default_factory=list)
    sections: list[ReportSection] = Field(default_factory=list)
    asset_inventory: ReportAssetInventory | None = None


class ExportResult(TechSpecterModel):
    """Result of exporting a report to a specific format."""

    format: ReportFormat
    content: str
    output_path: str | None = None
    byte_size: int = 0
