"""Integration tests for metadata analysis pipeline and reporting."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from techspecter.analysis.pipeline.pipeline import AnalysisPipeline
from techspecter.configuration.models import AnalysisConfig, MetadataAnalysisConfig
from techspecter.plugins.manager import PluginManager
from techspecter.reporting.service import ReportService
from tests.metadata_fixtures import sample_discovery_with_metadata


@pytest.mark.asyncio
async def test_pipeline_runs_metadata_analyzers_from_plugins() -> None:
    """Pipeline should execute built-in metadata analyzer plugins."""
    discovery = sample_discovery_with_metadata()
    manager = PluginManager()
    manager.load_plugins(load_builtins=True)
    pipeline = AnalysisPipeline(
        plugin_manager=manager,
        analysis_config=AnalysisConfig(
            enabled_analyzers=["robots-analyzer", "html-metadata-analyzer", "opengraph-analyzer"]
        ),
        metadata_config=MetadataAnalysisConfig(),
        load_builtin_plugins=False,
    )

    with patch.object(pipeline._discovery_pipeline, "run", AsyncMock(return_value=discovery)):
        result = await pipeline.run("https://example.com")

    analyzer_ids = {item.analyzer_id for item in result.analyzer_results}
    assert "robots-analyzer" in analyzer_ids
    assert result.findings


def test_metadata_configuration_disables_analyzer_group() -> None:
    """Metadata configuration should disable analyzer groups independently."""
    discovery = sample_discovery_with_metadata()
    manager = PluginManager()
    manager.load_plugins(load_builtins=True)
    pipeline = AnalysisPipeline(
        plugin_manager=manager,
        analysis_config=AnalysisConfig(enabled_analyzers=["robots-analyzer", "opengraph-analyzer"]),
        metadata_config=MetadataAnalysisConfig(robots=False, html_meta=True),
        load_builtin_plugins=False,
    )
    result = pipeline.analyze_discovery(discovery)
    analyzer_ids = {item.analyzer_id for item in result.analyzer_results}
    assert "robots-analyzer" not in analyzer_ids
    assert "opengraph-analyzer" in analyzer_ids


def test_report_includes_metadata_sections() -> None:
    """Reports generated from analysis should include metadata sections."""
    discovery = sample_discovery_with_metadata()
    manager = PluginManager()
    manager.load_plugins(load_builtins=True)
    pipeline = AnalysisPipeline(
        plugin_manager=manager,
        analysis_config=AnalysisConfig(
            enabled_analyzers=[
                "robots-analyzer",
                "opengraph-analyzer",
                "framework-metadata-analyzer",
            ]
        ),
        load_builtin_plugins=False,
    )
    analysis = pipeline.analyze_discovery(discovery)
    report = ReportService().generate_report_from_analysis(analysis)
    section_ids = {section.id for section in report.sections}
    assert "metadata-summary" in section_ids
    assert "html-metadata" in section_ids
    assert "framework-metadata" in section_ids
    assert "well-known-resources" in section_ids
    assert "manifest-information" in section_ids
    assert "pwa-information" in section_ids
    assert "sourcemap-summary" in section_ids
    assert "passive-resource-summary" in section_ids
