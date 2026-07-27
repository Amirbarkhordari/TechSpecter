"""Tests for the plugin registry."""

from __future__ import annotations

import pytest

from techspecter.core.context import ScanContext
from techspecter.core.interfaces import Plugin, PluginMetadata, ScanResult
from techspecter.exceptions import PluginNotFoundError
from techspecter.plugins.registry import PluginRegistry


class _StubPlugin(Plugin):
    """Minimal plugin implementation for testing."""

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="stub",
            version="0.0.1",
            description="Test stub plugin",
        )

    def execute(self, context: ScanContext) -> ScanResult:
        return ScanResult(plugin_name="stub", findings={"target": context.target_url})


def test_register_and_get_plugin() -> None:
    """Verify plugins can be registered and retrieved by name."""
    reg = PluginRegistry()
    plugin = _StubPlugin()
    reg.register(plugin)
    assert reg.get("stub") is plugin
    assert reg.find("stub") is plugin
    assert reg.exists("stub")
    assert reg.list_plugins() == ["stub"]
    assert reg.list() == ("stub",)
    reg.unregister("stub")


def test_find_missing_returns_none() -> None:
    """Verify find returns None for unknown plugins."""
    reg = PluginRegistry()
    assert reg.find("missing") is None
    assert not reg.exists("missing")


def test_register_duplicate_raises() -> None:
    """Verify registering the same plugin twice raises ValueError."""
    reg = PluginRegistry()
    reg.register(_StubPlugin())
    with pytest.raises(ValueError, match="already registered"):
        reg.register(_StubPlugin())
    reg.clear()


def test_get_missing_plugin_raises() -> None:
    """Verify retrieving an unknown plugin raises PluginNotFoundError."""
    reg = PluginRegistry()
    with pytest.raises(PluginNotFoundError, match="not found"):
        reg.get("nonexistent")
