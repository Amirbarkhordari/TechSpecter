"""Reporting service orchestration."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from techspecter.analysis.results.analysis_result import AnalysisResult
from techspecter.exceptions import ExportError
from techspecter.fingerprinting.models import DetectionResult
from techspecter.reporting.engine import ReportEngine
from techspecter.reporting.exporters.base import BaseExporter
from techspecter.reporting.exporters.csv_exporter import CsvExporter
from techspecter.reporting.exporters.html_exporter import HtmlExporter
from techspecter.reporting.exporters.json_exporter import JsonExporter
from techspecter.reporting.exporters.markdown_exporter import MarkdownExporter
from techspecter.reporting.exporters.sarif_exporter import SarifExporter
from techspecter.reporting.models import ExportResult, Report, ReportFormat

logger = logging.getLogger(__name__)

_DEFAULT_EXPORTERS: dict[ReportFormat, BaseExporter] = {
    "json": JsonExporter(),
    "markdown": MarkdownExporter(),
    "html": HtmlExporter(),
    "csv": CsvExporter(),
    "sarif": SarifExporter(),
}


@dataclass(slots=True)
class ReportService:
    """Generate and export scan reports from detection results."""

    engine: ReportEngine | None = None
    exporters: dict[ReportFormat, BaseExporter] = field(
        default_factory=lambda: dict(_DEFAULT_EXPORTERS)
    )

    def generate_report(
        self,
        detection: DetectionResult,
        *,
        scan_duration_ms: float | None = None,
    ) -> Report:
        """Generate a structured report from detection output."""
        return self._engine().generate(detection, scan_duration_ms=scan_duration_ms)

    def generate_report_from_analysis(
        self,
        analysis: AnalysisResult,
        *,
        scan_duration_ms: float | None = None,
    ) -> Report:
        """Generate a structured report from generic analysis output."""
        return self._engine().generate_from_analysis(analysis, scan_duration_ms=scan_duration_ms)

    def export_report(
        self,
        report: Report,
        report_format: ReportFormat,
        *,
        output_path: Path | str | None = None,
    ) -> ExportResult:
        """Export a report to the requested format."""
        exporter = self.exporters.get(report_format)
        if exporter is None:
            msg = f"Unsupported report format: {report_format}"
            raise ExportError(msg)

        logger.info("Exporting report as %s", report_format)
        content = exporter.export(report)
        path = Path(output_path) if output_path else None

        if path is not None:
            logger.info("Writing report to %s", path)
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            except OSError as exc:
                msg = f"Unable to write report to {path}"
                raise ExportError(msg) from exc

        result = ExportResult(
            format=report_format,
            content=content,
            output_path=str(path) if path else None,
            byte_size=len(content.encode("utf-8")),
        )
        logger.info("Export completed (%d bytes)", result.byte_size)
        return result

    def generate_and_export(
        self,
        detection: DetectionResult,
        report_format: ReportFormat,
        *,
        output_path: Path | str | None = None,
        scan_duration_ms: float | None = None,
    ) -> ExportResult:
        """Generate a report and export it in one operation."""
        report = self.generate_report(detection, scan_duration_ms=scan_duration_ms)
        return self.export_report(report, report_format, output_path=output_path)

    def generate_and_export_from_analysis(
        self,
        analysis: AnalysisResult,
        report_format: ReportFormat,
        *,
        output_path: Path | str | None = None,
        scan_duration_ms: float | None = None,
    ) -> ExportResult:
        """Generate a report from analysis output and export it."""
        report = self.generate_report_from_analysis(analysis, scan_duration_ms=scan_duration_ms)
        return self.export_report(report, report_format, output_path=output_path)

    def _engine(self) -> ReportEngine:
        """Return the configured report engine."""
        if self.engine is None:
            self.engine = ReportEngine()
        return self.engine
