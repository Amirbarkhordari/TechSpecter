"""Tests for plugin services and enriched context."""

from __future__ import annotations

from unittest.mock import patch

from techspecter.plugins.manager import PluginManager
from tests.plugin_fixtures import RecordingLifecyclePlugin


def test_context_includes_services() -> None:
    """Verify manager builds plugin context with services."""
    plugin = RecordingLifecyclePlugin()
    manager = PluginManager()
    with patch(
        "techspecter.plugins.manager.PluginLoader",
    ) as loader_cls:
        loader_cls.return_value.load_all.return_value = [plugin]
        manager.load_plugins(load_entry_points=False)

    context = manager.get_context("sample-plugin")
    assert context is not None
    assert context.services is not None
    assert context.services.version
    assert context.services.registry is manager.registry
    assert context.services.manager is manager
    manager.shutdown()
