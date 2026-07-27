"""Tests for the report generation engine."""

from __future__ import annotations

from techspecter.reporting.engine import ReportEngine
from tests.report_fixtures import sample_detection_result


def test_report_engine_generates_metadata() -> None:
    """Verify report metadata is populated from detection results."""
    report = ReportEngine().generate(sample_detection_result(), scan_duration_ms=200.0)
    assert report.metadata.target_url == "https://example.com"
    assert report.metadata.tool_name == "TechSpecter"
    assert report.metadata.technologies_detected == 2
    assert report.metadata.scripts_analyzed == 2
    assert report.metadata.scan_duration_ms == 200.0


def test_report_engine_calculates_statistics() -> None:
    """Verify report statistics are calculated correctly."""
    report = ReportEngine().generate(sample_detection_result())
    assert report.statistics.total_technologies == 2
    assert report.statistics.category_count == 2
    assert report.statistics.known_versions == 1
    assert report.statistics.unknown_versions == 1
    assert report.statistics.average_confidence == 85.25
    assert report.statistics.highest_confidence == 92.5


def test_report_engine_groups_technologies() -> None:
    """Verify technologies are grouped by category."""
    report = ReportEngine().generate(sample_detection_result())
    categories = {group.category for group in report.groups}
    assert categories == {"build-tool", "framework"}


def test_report_engine_maps_evidence() -> None:
    """Verify technology evidence is mapped into the report."""
    report = ReportEngine().generate(sample_detection_result())
    react = next(item for item in report.technologies if item.id == "react")
    assert react.evidence
    assert react.evidence[0].matcher_type == "string"
    assert react.evidence[0].matched_file == "react.js"
