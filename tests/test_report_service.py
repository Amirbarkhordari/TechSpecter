"""Tests for the reporting service."""

from __future__ import annotations

from pathlib import Path

from techspecter.reporting.service import ReportService
from tests.report_fixtures import sample_detection_result


def test_report_service_exports_to_file(tmp_path: Path) -> None:
    """Verify the service writes exported reports to disk."""
    output = tmp_path / "report.html"
    result = ReportService().generate_and_export(
        sample_detection_result(),
        "html",
        output_path=output,
    )
    assert result.output_path == str(output)
    assert output.exists()
    assert "TechSpecter Scan Report" in output.read_text(encoding="utf-8")


def test_report_service_returns_content_without_output_path() -> None:
    """Verify export content is returned when no output path is provided."""
    result = ReportService().generate_and_export(sample_detection_result(), "markdown")
    assert result.content
    assert result.output_path is None
    assert result.byte_size > 0


def test_report_service_supports_all_formats() -> None:
    """Verify all supported export formats succeed."""
    service = ReportService()
    detection = sample_detection_result()
    for report_format in ("json", "markdown", "html", "csv", "sarif"):
        result = service.generate_and_export(detection, report_format)  # type: ignore[arg-type]
        assert result.format == report_format
        assert result.content
