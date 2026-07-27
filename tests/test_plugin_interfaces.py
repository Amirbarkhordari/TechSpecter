"""Tests for typed plugin interfaces."""

from __future__ import annotations

from pathlib import Path

from techspecter.analysis.analyzers.base import Analyzer, AnalyzerMetadata
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.core.context import ScanContext
from techspecter.models.discovery import DiscoveryResult
from techspecter.plugins.interfaces import (
    AnalyzerPlugin,
    ExporterPlugin,
    ReporterPlugin,
    RulePackPlugin,
    plugin_type_for,
)
from techspecter.plugins.metadata import PluginType
from techspecter.reporting.engine import ReportEngine
from techspecter.reporting.exporters.base import BaseExporter
from techspecter.reporting.models import Report, ReportFormat
from tests.plugin_fixtures import sample_metadata


class _ExampleAnalyzer(Analyzer):
    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="example",
            name="Example",
            version="1.0.0",
            description="Example analyzer",
            category="information",
        )

    def execute(self, discovery: DiscoveryResult) -> AnalyzerResult:
        return AnalyzerResult(analyzer_id="example", findings=[])


class _ExampleExporter(BaseExporter):
    format: ReportFormat = "json"

    def export(self, report: Report) -> str:
        return "{}"


class _AnalyzerPlugin(AnalyzerPlugin):
    @property
    def plugin_metadata(self):
        return sample_metadata(id="analyzer-plugin", plugin_type=PluginType.ANALYZER)

    def analyzers(self):
        return [_ExampleAnalyzer()]

    def execute(self, context: ScanContext):
        return super().execute(context)


class _ReporterPlugin(ReporterPlugin):
    @property
    def plugin_metadata(self):
        return sample_metadata(id="reporter-plugin", plugin_type=PluginType.REPORTER)

    def report_engines(self):
        return {"custom": ReportEngine(tool_name="Custom")}

    def execute(self, context: ScanContext):
        return super().execute(context)


class _ExporterPlugin(ExporterPlugin):
    @property
    def plugin_metadata(self):
        return sample_metadata(id="exporter-plugin", plugin_type=PluginType.EXPORTER)

    def exporters(self):
        return {"custom": _ExampleExporter()}

    def execute(self, context: ScanContext):
        return super().execute(context)


class _RulePackPlugin(RulePackPlugin):
    @property
    def plugin_metadata(self):
        return sample_metadata(id="rules-plugin", plugin_type=PluginType.RULE_PACK)

    def rule_directories(self):
        return [Path("/tmp/rules")]

    def execute(self, context: ScanContext):
        return super().execute(context)


def test_analyzer_plugin_exposes_analyzers() -> None:
    """Verify analyzer plugins expose analyzer resources."""
    plugin = _AnalyzerPlugin()
    assert plugin_type_for(plugin) == PluginType.ANALYZER
    assert plugin.analyzers()[0].metadata.id == "example"


def test_reporter_plugin_exposes_engines() -> None:
    """Verify reporter plugins expose report engines."""
    plugin = _ReporterPlugin()
    assert "custom" in plugin.report_engines()


def test_exporter_plugin_exposes_exporters() -> None:
    """Verify exporter plugins expose exporters."""
    plugin = _ExporterPlugin()
    assert "custom" in plugin.exporters()


def test_rule_pack_plugin_exposes_directories() -> None:
    """Verify rule pack plugins expose rule directories."""
    plugin = _RulePackPlugin()
    assert plugin.rule_directories() == [Path("/tmp/rules")]
