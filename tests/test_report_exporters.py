"""Tests for report exporters."""

from __future__ import annotations

import csv
import io
import json

from techspecter.reporting.engine import ReportEngine
from techspecter.reporting.exporters.csv_exporter import CsvExporter
from techspecter.reporting.exporters.html_exporter import HtmlExporter
from techspecter.reporting.exporters.json_exporter import JsonExporter
from techspecter.reporting.exporters.markdown_exporter import MarkdownExporter
from techspecter.reporting.exporters.sarif_exporter import SarifExporter
from tests.report_fixtures import sample_detection_result


def _report():
    return ReportEngine().generate(sample_detection_result())


def test_json_exporter_includes_metadata_and_technologies() -> None:
    """Verify JSON export includes metadata and technologies."""
    payload = json.loads(JsonExporter().export(_report()))
    assert payload["metadata"]["target_url"] == "https://example.com"
    assert len(payload["technologies"]) == 2
    assert payload["statistics"]["total_technologies"] == 2


def test_markdown_exporter_contains_required_sections() -> None:
    """Verify Markdown export contains required sections."""
    content = MarkdownExporter().export(_report())
    assert "# TechSpecter Scan Report" in content
    assert "## Summary" in content
    assert "## Statistics" in content
    assert "## Detected Technologies" in content
    assert "## Evidence" in content
    assert "React" in content


def test_html_exporter_renders_template() -> None:
    """Verify HTML export renders a complete document."""
    content = HtmlExporter().export(_report())
    assert "<!DOCTYPE html>" in content
    assert "TechSpecter Scan Report" in content
    assert "React" in content
    assert "confidence high" in content


def test_csv_exporter_writes_one_row_per_technology() -> None:
    """Verify CSV export writes one row per technology."""
    content = CsvExporter().export(_report())
    rows = list(csv.reader(io.StringIO(content)))
    assert rows[0] == [
        "Technology",
        "Category",
        "Version",
        "Confidence",
        "Evidence",
        "Source File",
    ]
    assert len(rows) == 3


def test_sarif_exporter_generates_valid_structure() -> None:
    """Verify SARIF export follows the SARIF 2.1.0 structure."""
    payload = json.loads(SarifExporter().export(_report()))
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "TechSpecter"
    assert len(payload["runs"][0]["results"]) == 2
    assert payload["runs"][0]["results"][0]["ruleId"] == "react"
