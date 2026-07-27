"""Tests for analyze CLI command."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from techspecter.analysis.results.analysis_result import AnalysisMetadata, AnalysisResult
from techspecter.analysis.statistics.statistics import AnalysisStatistics
from techspecter.cli import app
from tests.http_fixtures import sample_discovery_with_http


def _sample_analysis_result() -> AnalysisResult:
    discovery = sample_discovery_with_http()
    return AnalysisResult(
        target_url="https://example.com/",
        findings=[],
        statistics=AnalysisStatistics(total_findings=0),
        metadata=AnalysisMetadata(
            target_url="https://example.com/",
            tool_version="test",
            analyzers=["http-header-analyzer"],
        ),
        discovery=discovery,
        elapsed_ms=10.0,
    )


def test_analyze_command_runs_successfully() -> None:
    """Analyze command should invoke AnalysisService and render summary."""
    runner = CliRunner()
    with patch(
        "techspecter.analysis.service.AnalysisService.analyze_url",
        AsyncMock(return_value=_sample_analysis_result()),
    ):
        result = runner.invoke(app, ["analyze", "https://example.com"])
    assert result.exit_code == 0
    assert "Findings:" in result.stdout


def test_analyze_command_json_output() -> None:
    """Analyze command should support JSON output."""
    runner = CliRunner()
    with patch(
        "techspecter.analysis.service.AnalysisService.analyze_url",
        AsyncMock(return_value=_sample_analysis_result()),
    ):
        result = runner.invoke(app, ["analyze", "https://example.com", "--json"])
    assert result.exit_code == 0
    assert "target_url" in result.stdout


def test_analyze_command_headers_flag() -> None:
    """Analyze command should accept the headers selector flag."""
    runner = CliRunner()
    with patch(
        "techspecter.analysis.service.AnalysisService.analyze_url",
        AsyncMock(return_value=_sample_analysis_result()),
    ):
        result = runner.invoke(app, ["analyze", "https://example.com", "--headers"])
    assert result.exit_code == 0
