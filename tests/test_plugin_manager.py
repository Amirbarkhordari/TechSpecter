"""Tests for plugin manager."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from techspecter.plugins.config import PluginConfigEntry, PluginConfiguration
from techspecter.plugins.manager import PluginManager
from tests.plugin_fixtures import RecordingLifecyclePlugin, sample_metadata, write_directory_plugin


def _mock_loader(*plugins: object) -> MagicMock:
    """Return a loader mock that yields the given plugins."""
    loader = MagicMock()
    loader.load_all.return_value = list(plugins)
    return loader


def test_manager_loads_directory_plugin(tmp_path: Path) -> None:
    """Verify manager loads and registers directory plugins."""
    write_directory_plugin(tmp_path, plugin_id="managed-plugin")
    manager = PluginManager(
        configuration=PluginConfiguration(plugin_directories=[str(tmp_path)]),
    )
    loaded = manager.load_plugins(load_entry_points=False)
    assert loaded == ["managed-plugin"]
    assert manager.registry.find("managed-plugin") is not None
    manager.shutdown()


def test_manager_skips_disabled_plugin(tmp_path: Path) -> None:
    """Verify disabled plugins are not loaded."""
    write_directory_plugin(tmp_path, plugin_id="disabled-plugin")
    manager = PluginManager(
        configuration=PluginConfiguration(
            plugin_directories=[str(tmp_path)],
            disabled_plugins=["disabled-plugin"],
        ),
    )
    loaded = manager.load_plugins(load_entry_points=False)
    assert loaded == []
    assert manager.registry.find("disabled-plugin") is None


def test_manager_runs_lifecycle_on_load() -> None:
    """Verify manager initializes plugins through lifecycle."""
    plugin = RecordingLifecyclePlugin(sample_metadata(id="lifecycle-plugin"))
    manager = PluginManager()
    with patch(
        "techspecter.plugins.manager.PluginLoader",
        return_value=_mock_loader(plugin),
    ):
        loaded = manager.load_plugins(load_entry_points=False)
    assert loaded == ["lifecycle-plugin"]
    assert plugin.calls == ["initialize", "register", "start", "enable"]
    manager.shutdown()
    assert "shutdown" in plugin.calls
    assert "cleanup" in plugin.calls


def test_manager_skips_failed_initialization() -> None:
    """Verify plugins that fail initialization are not registered."""
    plugin = RecordingLifecyclePlugin(sample_metadata(id="broken-plugin"))

    def fail_initialize(context: object) -> None:
        raise RuntimeError("cannot initialize")

    plugin.initialize = fail_initialize  # type: ignore[method-assign]
    manager = PluginManager()
    with patch(
        "techspecter.plugins.manager.PluginLoader",
        return_value=_mock_loader(plugin),
    ):
        loaded = manager.load_plugins(load_entry_points=False)
    assert loaded == []
    assert manager.registry.find("broken-plugin") is None


def test_manager_applies_plugin_settings() -> None:
    """Verify manager passes configured settings into plugin context."""
    plugin = RecordingLifecyclePlugin(sample_metadata(id="settings-plugin"))
    manager = PluginManager(
        configuration=PluginConfiguration(
            plugins={
                "settings-plugin": PluginConfigEntry(
                    settings={"feature": True},
                ),
            },
        ),
    )
    with patch(
        "techspecter.plugins.manager.PluginLoader",
        return_value=_mock_loader(plugin),
    ):
        manager.load_plugins(load_entry_points=False)
    context = manager._contexts["settings-plugin"]
    assert context.settings.get("feature") is True
    manager.shutdown()
