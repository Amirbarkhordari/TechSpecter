"""Tests for plugin lifecycle management."""

from __future__ import annotations

from techspecter.plugins.context import PluginContext, PluginLogger, PluginResources, PluginSettings
from techspecter.plugins.lifecycle import PluginLifecycle
from tests.plugin_fixtures import RecordingLifecyclePlugin


def _context(plugin: RecordingLifecyclePlugin) -> PluginContext:
    """Build a plugin context for lifecycle tests."""
    return PluginContext(
        metadata=plugin.plugin_metadata,
        settings=PluginSettings(),
        resources=PluginResources(),
        logger=PluginLogger(plugin.plugin_metadata.id),
    )


def test_initialize_runs_all_startup_hooks() -> None:
    """Verify initialize runs initialize, register, and start."""
    plugin = RecordingLifecyclePlugin()
    lifecycle = PluginLifecycle()
    lifecycle.initialize_plugin(plugin, _context(plugin))
    assert plugin.calls == ["initialize", "register", "start", "enable"]


def test_shutdown_runs_all_teardown_hooks() -> None:
    """Verify shutdown runs shutdown and cleanup."""
    plugin = RecordingLifecyclePlugin()
    lifecycle = PluginLifecycle()
    context = _context(plugin)
    lifecycle.initialize_plugin(plugin, context)
    plugin.calls.clear()
    lifecycle.shutdown_plugin(plugin, context)
    assert plugin.calls == ["disable", "shutdown", "cleanup"]


def test_safe_initialize_returns_false_on_failure() -> None:
    """Verify safe_initialize catches initialization errors."""
    plugin = RecordingLifecyclePlugin()

    def fail_initialize(context: PluginContext) -> None:
        raise RuntimeError("init failed")

    plugin.initialize = fail_initialize  # type: ignore[method-assign]
    lifecycle = PluginLifecycle()
    assert lifecycle.safe_initialize(plugin, _context(plugin)) is False


def test_safe_shutdown_swallows_errors() -> None:
    """Verify safe_shutdown catches shutdown errors."""
    plugin = RecordingLifecyclePlugin()

    def fail_shutdown(context: PluginContext) -> None:
        raise RuntimeError("shutdown failed")

    plugin.shutdown = fail_shutdown  # type: ignore[method-assign]
    lifecycle = PluginLifecycle()
    lifecycle.safe_shutdown(plugin, _context(plugin))
