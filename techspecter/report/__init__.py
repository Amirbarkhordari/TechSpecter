"""Backward-compatible re-exports for the reporting engine."""

from techspecter.reporting import (
    ExportResult,
    Report,
    ReportEngine,
    ReportFormat,
    ReportService,
    render_report,
)

__all__ = [
    "ExportResult",
    "Report",
    "ReportEngine",
    "ReportFormat",
    "ReportService",
    "render_report",
]
