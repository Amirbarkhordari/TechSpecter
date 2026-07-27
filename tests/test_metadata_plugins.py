"""Tests for built-in metadata analyzer plugin registration."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzer_ids import METADATA_ANALYZER_IDS
from techspecter.plugins.interfaces import AnalyzerPlugin
from techspecter.plugins.manager import PluginManager


def test_builtin_metadata_plugins_load() -> None:
    """Built-in metadata analyzer plugins should load through PluginManager."""
    manager = PluginManager()
    loaded = manager.load_plugins(load_builtins=True)
    assert len(loaded) >= 34


def test_collect_metadata_analyzers() -> None:
    """PluginManager should collect all metadata analyzer implementations."""
    manager = PluginManager()
    manager.load_plugins(load_builtins=True)
    analyzer_ids = {analyzer.metadata.id for analyzer in manager.collect_analyzers()}
    for analyzer_id in METADATA_ANALYZER_IDS:
        assert analyzer_id in analyzer_ids


def test_metadata_plugins_are_analyzer_plugins() -> None:
    """Metadata plugins should implement AnalyzerPlugin."""
    manager = PluginManager()
    manager.load_plugins(load_builtins=True)
    metadata_ids = {
        plugin.plugin_metadata.id
        for plugin in manager.registry.list_instances()
        if any(
            analyzer_id.replace("-analyzer", "") in plugin.plugin_metadata.id
            for analyzer_id in METADATA_ANALYZER_IDS
        )
    }
    assert len(metadata_ids) >= len(METADATA_ANALYZER_IDS)
    for plugin in manager.registry.list_instances():
        if plugin.plugin_metadata.id in metadata_ids:
            assert isinstance(plugin, AnalyzerPlugin)
            assert plugin.analyzers()
