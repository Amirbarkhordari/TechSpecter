"""Performance tests for report generation."""

from __future__ import annotations

import time

from techspecter.fingerprinting.models import PatternEvidence, Technology, TechnologyMatch
from techspecter.reporting.engine import ReportEngine
from techspecter.reporting.exporters.html_exporter import HtmlExporter
from techspecter.reporting.service import ReportService
from tests.report_fixtures import sample_detection_result


def test_large_report_generation_is_efficient() -> None:
    """Verify generating and exporting large reports stays efficient."""
    matches = [
        TechnologyMatch(
            technology=Technology(
                id=f"tech-{index}",
                name=f"Technology {index}",
                category=f"category-{index % 5}",
            ),
            version="1.0.0",
            confidence=50.0 + (index % 50),
            filename=f"script-{index}.js",
            evidence=[
                PatternEvidence(
                    matcher="string",
                    pattern=f"marker-{index}",
                    weight=10.0,
                )
            ],
        )
        for index in range(100)
    ]
    detection = sample_detection_result().model_copy(update={"matches": matches})

    started = time.perf_counter()
    report = ReportEngine().generate(detection)
    html = HtmlExporter().export(report)
    elapsed_ms = (time.perf_counter() - started) * 1000

    assert len(report.technologies) == 100
    assert "Technology 0" in html
    assert elapsed_ms < 2000


def test_report_service_handles_large_csv_export() -> None:
    """Verify CSV export scales for large technology lists."""
    matches = [
        TechnologyMatch(
            technology=Technology(
                id=f"tech-{index}",
                name=f"Technology {index}",
                category="library",
            ),
            version="Unknown",
            confidence=60.0,
        )
        for index in range(200)
    ]
    detection = sample_detection_result().model_copy(update={"matches": matches})
    content = ReportService().generate_and_export(detection, "csv").content
    assert content.count("\n") >= 200
