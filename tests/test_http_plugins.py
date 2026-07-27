"""Tests for built-in HTTP analyzer plugin registration."""

from __future__ import annotations

from techspecter.analysis.http.analyzer_ids import HTTP_ANALYZER_IDS, HTTP_ANALYZER_PLUGIN_IDS
from techspecter.plugins.interfaces import AnalyzerPlugin
from techspecter.plugins.manager import PluginManager


def test_builtin_http_plugins_load() -> None:
    """Built-in HTTP analyzer plugins should load through PluginManager."""
    manager = PluginManager()
    loaded = manager.load_plugins(load_builtins=True)
    http_plugins = [item for item in loaded if item.endswith("-plugin") and "analyzer" in item]
    assert len(http_plugins) >= len(HTTP_ANALYZER_PLUGIN_IDS)


def test_collect_analyzers_returns_http_analyzers() -> None:
    """PluginManager should collect all HTTP analyzer implementations."""
    manager = PluginManager()
    manager.load_plugins(load_builtins=True)
    analyzer_ids = {analyzer.metadata.id for analyzer in manager.collect_analyzers()}
    for analyzer_id in HTTP_ANALYZER_IDS:
        assert analyzer_id in analyzer_ids


def test_each_http_plugin_is_analyzer_plugin() -> None:
    """Every built-in HTTP plugin should implement AnalyzerPlugin."""
    manager = PluginManager()
    manager.load_plugins(load_builtins=True)
    for plugin in manager.registry.list_instances():
        if plugin.plugin_metadata.id in HTTP_ANALYZER_PLUGIN_IDS:
            assert isinstance(plugin, AnalyzerPlugin)
            assert plugin.analyzers()
