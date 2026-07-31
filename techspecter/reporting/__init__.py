"""Reporting engine for scan result export and presentation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from techspecter.reporting.models import (
    ExportResult,
    Report,
    ReportEvidence,
    ReportFormat,
    ReportMetadata,
    ReportStatistics,
    ReportSummary,
    ReportTarget,
    ReportTechnology,
    TechnologyGroup,
)

if TYPE_CHECKING:
    from techspecter.reporting.engine import ReportEngine
    from techspecter.reporting.service import ReportService

__all__ = [
    "ExportResult",
    "Report",
    "ReportEngine",
    "ReportEvidence",
    "ReportFormat",
    "ReportMetadata",
    "ReportService",
    "ReportStatistics",
    "ReportSummary",
    "ReportTarget",
    "ReportTechnology",
    "TechnologyGroup",
    "render_report",
]


def __getattr__(name: str) -> object:
    """Lazy-load heavy reporting components to avoid import cycles."""
    if name == "ReportEngine":
        from techspecter.reporting.engine import ReportEngine

        return ReportEngine
    if name == "ReportService":
        from techspecter.reporting.service import ReportService

        return ReportService
    if name == "render_report":
        from techspecter.reporting.renderer import render_report

        return render_report
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
