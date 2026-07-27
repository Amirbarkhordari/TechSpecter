"""Tests for example plugins."""

from __future__ import annotations

from techspecter.plugins.examples.example_analyzer_plugin import ExampleAnalyzerPlugin
from techspecter.plugins.examples.example_reporter_plugin import ExampleReporterPlugin
from techspecter.plugins.examples.example_rule_pack_plugin import ExampleRulePackPlugin
from techspecter.plugins.metadata import PluginType
from techspecter.plugins.validator import PluginValidator


def test_example_analyzer_plugin_validates() -> None:
    """Verify example analyzer plugin validates."""
    plugin = ExampleAnalyzerPlugin()
    report = PluginValidator().validate(plugin)
    assert report.is_valid
    assert plugin.plugin_metadata.plugin_type == PluginType.ANALYZER
    assert plugin.analyzers()


def test_example_reporter_plugin_validates() -> None:
    """Verify example reporter plugin validates."""
    plugin = ExampleReporterPlugin()
    report = PluginValidator().validate(plugin)
    assert report.is_valid
    assert plugin.report_engines()


def test_example_rule_pack_plugin_validates() -> None:
    """Verify example rule pack plugin validates."""
    plugin = ExampleRulePackPlugin()
    report = PluginValidator().validate(plugin)
    assert report.is_valid
    assert plugin.rule_directories()
