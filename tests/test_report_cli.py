"""Tests for reporting CLI integration."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from techspecter.cli import app
from techspecter.fingerprinting.models import (
    DetectionResult,
    FingerprintAnalysisResult,
    Technology,
    TechnologyMatch,
)

runner = CliRunner()


def _analysis_result() -> FingerprintAnalysisResult:
    return FingerprintAnalysisResult(
        target_url="https://example.com",
        detection=DetectionResult(
            target_url="https://example.com",
            matches=[
                TechnologyMatch(
                    technology=Technology(id="react", name="React", category="framework"),
                    version="18.2.0",
                    confidence=92.5,
                    filename="react.js",
                )
            ],
            scripts_analyzed=1,
            elapsed_ms=50.0,
        ),
        elapsed_ms=100.0,
    )


def test_fingerprint_command_help_lists_report_formats() -> None:
    """Verify fingerprint help lists report format options."""
    result = runner.invoke(app, ["fingerprint", "--help"])
    assert result.exit_code == 0
    assert "--format" in result.stdout
    assert "--output" in result.stdout


@patch("techspecter.cli.FingerprintService.analyze_url", new_callable=AsyncMock)
def test_fingerprint_command_exports_markdown(mock_analyze: AsyncMock) -> None:
    """Verify --format markdown prints a Markdown report."""
    mock_analyze.return_value = _analysis_result()
    result = runner.invoke(app, ["fingerprint", "https://example.com", "--format", "markdown"])
    assert result.exit_code == 0
    assert "# TechSpecter Scan Report" in result.stdout


@patch("techspecter.cli.FingerprintService.analyze_url", new_callable=AsyncMock)
def test_fingerprint_command_writes_html_output(mock_analyze: AsyncMock, tmp_path: Path) -> None:
    """Verify --format html --output writes an HTML file."""
    mock_analyze.return_value = _analysis_result()
    output = tmp_path / "report.html"
    result = runner.invoke(
        app,
        [
            "fingerprint",
            "https://example.com",
            "--format",
            "html",
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0
    assert output.exists()
    assert "Report written to" in result.stdout


@patch("techspecter.cli.FingerprintService.analyze_url", new_callable=AsyncMock)
def test_fingerprint_command_legacy_json_still_works(mock_analyze: AsyncMock) -> None:
    """Verify legacy --json output remains available."""
    mock_analyze.return_value = _analysis_result()
    result = runner.invoke(app, ["fingerprint", "https://example.com", "--json"])
    assert result.exit_code == 0
    assert '"target_url": "https://example.com"' in result.stdout
    assert '"detection"' in result.stdout
