"""Integration tests for HTTP analysis pipeline and reporting."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from techspecter.analysis.pipeline.pipeline import AnalysisPipeline
from techspecter.configuration.models import AnalysisConfig, HttpAnalysisConfig
from techspecter.plugins.manager import PluginManager
from techspecter.reporting.service import ReportService
from tests.http_fixtures import sample_discovery_with_http


@pytest.mark.asyncio
async def test_pipeline_runs_http_analyzers_from_plugins() -> None:
    """Pipeline should execute built-in HTTP analyzer plugins."""
    discovery = sample_discovery_with_http()
    manager = PluginManager()
    manager.load_plugins(load_builtins=True)
    pipeline = AnalysisPipeline(
        plugin_manager=manager,
        analysis_config=AnalysisConfig(
            enabled_analyzers=list(
                {
                    "http-header-analyzer",
                    "security-header-analyzer",
                    "cookie-analyzer",
                }
            )
        ),
        http_config=HttpAnalysisConfig(),
        load_builtin_plugins=False,
    )

    with patch.object(pipeline._discovery_pipeline, "run", AsyncMock(return_value=discovery)):
        result = await pipeline.run("https://example.com")

    analyzer_ids = {item.analyzer_id for item in result.analyzer_results}
    assert "http-header-analyzer" in analyzer_ids
    assert result.findings
    assert result.discovery is not None
    assert result.discovery.http_response is not None


def test_http_configuration_disables_analyzer_group() -> None:
    """HTTP configuration should disable analyzer groups independently."""
    discovery = sample_discovery_with_http()
    manager = PluginManager()
    manager.load_plugins(load_builtins=True)
    pipeline = AnalysisPipeline(
        plugin_manager=manager,
        analysis_config=AnalysisConfig(
            enabled_analyzers=["http-header-analyzer", "cookie-analyzer"]
        ),
        http_config=HttpAnalysisConfig(headers=False, cookies=True),
        load_builtin_plugins=False,
    )
    result = pipeline.analyze_discovery(discovery)
    analyzer_ids = {item.analyzer_id for item in result.analyzer_results}
    assert "http-header-analyzer" not in analyzer_ids
    assert "cookie-analyzer" in analyzer_ids


def test_report_includes_http_sections() -> None:
    """Reports generated from analysis should include HTTP sections."""
    discovery = sample_discovery_with_http()
    manager = PluginManager()
    manager.load_plugins(load_builtins=True)
    pipeline = AnalysisPipeline(
        plugin_manager=manager,
        analysis_config=AnalysisConfig(
            enabled_analyzers=["http-header-analyzer", "cookie-analyzer"]
        ),
        load_builtin_plugins=False,
    )
    analysis = pipeline.analyze_discovery(discovery)
    report = ReportService().generate_report_from_analysis(analysis)
    section_ids = {section.id for section in report.sections}
    assert "http-analysis" in section_ids
    assert "header-analysis" in section_ids
    assert "cookie-analysis" in section_ids
    assert "security-header-summary" in section_ids
    assert "http-statistics" in section_ids
    assert "analyzer-execution-summary" in section_ids
    assert "plugin-summary" in section_ids
