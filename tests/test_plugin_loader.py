"""Tests for plugin loader."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from techspecter.plugins.exceptions import PluginLoadError
from techspecter.plugins.loader import PluginLoader
from tests.plugin_fixtures import RecordingLifecyclePlugin, write_directory_plugin


def test_load_directory_plugin(tmp_path: Path) -> None:
    """Verify plugins can be loaded from an external directory."""
    write_directory_plugin(tmp_path)
    loader = PluginLoader(plugin_directories=[tmp_path], load_entry_points=False)
    plugins = loader.load_directory_plugins()
    assert len(plugins) == 1
    assert plugins[0].plugin_metadata.id == "dir-plugin"


def test_missing_directory_is_ignored(tmp_path: Path) -> None:
    """Verify missing directories are skipped gracefully."""
    loader = PluginLoader(
        plugin_directories=[tmp_path / "missing"],
        load_entry_points=False,
    )
    assert loader.load_directory_plugins() == []


def test_invalid_module_is_skipped(tmp_path: Path) -> None:
    """Verify import failures do not crash loading."""
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    (plugin_dir / "broken.py").write_text("raise RuntimeError('boom')\n", encoding="utf-8")
    loader = PluginLoader(plugin_directories=[plugin_dir], load_entry_points=False)
    assert loader.load_directory_plugins() == []


def test_module_without_plugin_export_is_skipped(tmp_path: Path) -> None:
    """Verify modules without plugin exports are ignored."""
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    (plugin_dir / "empty.py").write_text("VALUE = 1\n", encoding="utf-8")
    loader = PluginLoader(plugin_directories=[plugin_dir], load_entry_points=False)
    assert loader.load_directory_plugins() == []


def test_load_entry_point_plugin() -> None:
    """Verify entry point plugins are loaded when available."""
    plugin = RecordingLifecyclePlugin()
    entry = MagicMock()
    entry.name = "test-entry"
    entry.load.return_value = plugin

    loader = PluginLoader(plugin_directories=[], load_entry_points=True)
    with patch("techspecter.plugins.loader.entry_points", return_value=[entry]):
        loaded = loader.load_entry_point_plugins()
    assert loaded == [plugin]


def test_entry_point_load_failure_is_graceful() -> None:
    """Verify entry point failures are logged and skipped."""
    entry = MagicMock()
    entry.name = "broken-entry"
    entry.load.side_effect = ImportError("missing dependency")

    loader = PluginLoader(plugin_directories=[], load_entry_points=True)
    with patch("techspecter.plugins.loader.entry_points", return_value=[entry]):
        assert loader.load_entry_point_plugins() == []


def test_builtins_disabled_by_default() -> None:
    """Verify built-in plugins are not loaded unless requested."""
    loader = PluginLoader(plugin_directories=[], load_entry_points=False, load_builtins=False)
    assert loader.load_builtin_plugins() == []


def test_coerce_plugin_rejects_invalid_object() -> None:
    """Verify non-plugin objects raise PluginLoadError."""
    loader = PluginLoader(plugin_directories=[], load_entry_points=False)
    with pytest.raises(PluginLoadError, match="not a Plugin"):
        loader._coerce_plugin(object(), source="test")
