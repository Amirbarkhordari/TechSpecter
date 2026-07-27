"""Integration tests for sensitive artifact analysis."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzer_ids import SENSITIVE_ARTIFACT_ANALYZER_IDS
from techspecter.analysis.pipeline.pipeline import AnalysisPipeline
from techspecter.configuration.models import AnalysisConfig, ArtifactAnalysisConfig
from techspecter.plugins.manager import PluginManager
from techspecter.reporting.engine import ReportEngine
from tests.sensitive_fixtures import sample_discovery_with_sensitive_artifacts


def test_pipeline_runs_sensitive_analyzers() -> None:
    """Pipeline should extract sensitive artifacts and run analyzers."""
    manager = PluginManager()
    manager.load_plugins(load_builtins=True)
    pipeline = AnalysisPipeline(
        plugin_manager=manager,
        analysis_config=AnalysisConfig(enabled_analyzers=list(SENSITIVE_ARTIFACT_ANALYZER_IDS)),
        artifact_config=ArtifactAnalysisConfig(sensitive_analysis=True),
        load_builtin_plugins=False,
    )
    discovery = sample_discovery_with_sensitive_artifacts(artifact_observation=None)
    result = pipeline.analyze_discovery(discovery)
    assert result.discovery is not None
    assert result.discovery.artifact_observation is not None
    assert result.findings


def test_config_disables_secret_analysis() -> None:
    """Config should disable secret pattern analyzer."""
    manager = PluginManager()
    manager.load_plugins(load_builtins=True)
    pipeline = AnalysisPipeline(
        plugin_manager=manager,
        analysis_config=AnalysisConfig(enabled_analyzers=list(SENSITIVE_ARTIFACT_ANALYZER_IDS)),
        artifact_config=ArtifactAnalysisConfig(secret_analysis=False),
        load_builtin_plugins=False,
    )
    result = pipeline.analyze_discovery(sample_discovery_with_sensitive_artifacts())
    analyzer_ids = {item.analyzer_id for item in result.analyzer_results}
    assert "secret-pattern-analyzer" not in analyzer_ids


def test_report_includes_sensitive_sections() -> None:
    """Report should include Part 2 sensitive artifact sections."""
    manager = PluginManager()
    manager.load_plugins(load_builtins=True)
    pipeline = AnalysisPipeline(
        plugin_manager=manager,
        analysis_config=AnalysisConfig(enabled_analyzers=list(SENSITIVE_ARTIFACT_ANALYZER_IDS)),
        artifact_config=ArtifactAnalysisConfig(),
        load_builtin_plugins=False,
    )
    analysis = pipeline.analyze_discovery(sample_discovery_with_sensitive_artifacts())
    report = ReportEngine().generate_from_analysis(analysis)
    section_ids = {section.id for section in report.sections}
    assert "sensitive-secrets" in section_ids
    assert "risk-classification" in section_ids
    assert "executive-summary" in section_ids
