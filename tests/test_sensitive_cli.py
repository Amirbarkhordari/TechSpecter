"""Tests for sensitive artifact CLI command."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from techspecter.analysis.results.analysis_result import AnalysisMetadata, AnalysisResult
from techspecter.analysis.statistics.statistics import AnalysisStatistics
from techspecter.cli import app
from tests.sensitive_fixtures import sample_discovery_with_sensitive_artifacts


def _sample_analysis_result() -> AnalysisResult:
    discovery = sample_discovery_with_sensitive_artifacts()
    return AnalysisResult(
        target_url="https://example.com/",
        findings=[],
        statistics=AnalysisStatistics(total_findings=0),
        metadata=AnalysisMetadata(
            target_url="https://example.com/",
            tool_version="test",
            analyzers=["secret-pattern-analyzer"],
        ),
        discovery=discovery,
        elapsed_ms=10.0,
    )


def test_sensitive_command_runs() -> None:
    """Sensitive command should invoke analysis service."""
    runner = CliRunner()
    with patch(
        "techspecter.analysis.service.AnalysisService.analyze_url",
        AsyncMock(return_value=_sample_analysis_result()),
    ):
        result = runner.invoke(app, ["sensitive", "https://example.com", "--secret-analysis"])
    assert result.exit_code == 0
    assert "Findings:" in result.stdout


def test_sensitive_command_json_output() -> None:
    """Sensitive command should support JSON output."""
    runner = CliRunner()
    with patch(
        "techspecter.analysis.service.AnalysisService.analyze_url",
        AsyncMock(return_value=_sample_analysis_result()),
    ):
        result = runner.invoke(app, ["sensitive", "https://example.com", "--json"])
    assert result.exit_code == 0
    assert "target_url" in result.stdout
