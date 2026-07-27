"""Integration tests for artifact analysis pipeline."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzer_ids import ARTIFACT_ANALYZER_IDS
from techspecter.analysis.pipeline.pipeline import AnalysisPipeline
from techspecter.configuration.models import AnalysisConfig, ArtifactAnalysisConfig
from techspecter.plugins.manager import PluginManager
from techspecter.reporting.engine import ReportEngine
from tests.artifact_fixtures import sample_discovery_with_artifacts


def test_pipeline_extracts_artifacts_and_runs_analyzers() -> None:
    """Pipeline should extract artifacts and run artifact analyzers."""
    manager = PluginManager()
    manager.load_plugins(load_builtins=True)
    pipeline = AnalysisPipeline(
        plugin_manager=manager,
        analysis_config=AnalysisConfig(enabled_analyzers=list(ARTIFACT_ANALYZER_IDS)),
        artifact_config=ArtifactAnalysisConfig(),
        load_builtin_plugins=False,
    )
    discovery = sample_discovery_with_artifacts(artifact_observation=None)
    result = pipeline.analyze_discovery(discovery)
    assert result.discovery is not None
    assert result.discovery.artifact_observation is not None
    assert result.findings
    assert any(finding.metadata.get("source") == "passive-artifact" for finding in result.findings)


def test_artifact_config_disables_graphql() -> None:
    """Artifact config should disable specific analyzer groups."""
    manager = PluginManager()
    manager.load_plugins(load_builtins=True)
    pipeline = AnalysisPipeline(
        plugin_manager=manager,
        analysis_config=AnalysisConfig(enabled_analyzers=list(ARTIFACT_ANALYZER_IDS)),
        artifact_config=ArtifactAnalysisConfig(graphql=False),
        load_builtin_plugins=False,
    )
    result = pipeline.analyze_discovery(sample_discovery_with_artifacts())
    analyzer_ids = {item.analyzer_id for item in result.analyzer_results}
    assert "graphql-metadata-analyzer" not in analyzer_ids


def test_report_includes_artifact_sections() -> None:
    """Report engine should include artifact report sections."""
    manager = PluginManager()
    manager.load_plugins(load_builtins=True)
    pipeline = AnalysisPipeline(
        plugin_manager=manager,
        analysis_config=AnalysisConfig(enabled_analyzers=list(ARTIFACT_ANALYZER_IDS)),
        artifact_config=ArtifactAnalysisConfig(),
        load_builtin_plugins=False,
    )
    analysis = pipeline.analyze_discovery(sample_discovery_with_artifacts())
    report = ReportEngine().generate_from_analysis(analysis)
    section_ids = {section.id for section in report.sections}
    assert "cloud-services" in section_ids
    assert "identity-services" in section_ids
    assert "graphql" in section_ids
    assert "openapi" in section_ids
    assert "artifact-analyzer-summary" in section_ids
