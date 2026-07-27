"""Plugin loader."""

from __future__ import annotations

import importlib
import logging
from collections.abc import Iterable
from importlib.metadata import EntryPoint, entry_points
from pathlib import Path
from typing import cast

from techspecter.core.interfaces import Plugin as LegacyPlugin
from techspecter.plugins.discovery import (
    discover_modules_in_directory,
    extract_plugin_from_module,
    import_module_from_directory,
)
from techspecter.plugins.exceptions import PluginLoadError
from techspecter.plugins.interfaces import Plugin

logger = logging.getLogger(__name__)

ENTRYPOINT_GROUP = "techspecter.plugins"
BUILTIN_PACKAGE = "techspecter.plugins.builtin"


class PluginLoader:
    """Load plugins from built-ins, directories, and entry points."""

    def __init__(
        self,
        *,
        plugin_directories: Iterable[str | Path] | None = None,
        load_entry_points: bool = True,
        load_builtins: bool = False,
    ) -> None:
        """Initialize the plugin loader."""
        self._plugin_directories = [Path(item) for item in (plugin_directories or [])]
        self._load_entry_points = load_entry_points
        self._load_builtins = load_builtins

    def load_all(self) -> list[Plugin | LegacyPlugin]:
        """Load plugins from all configured sources."""
        plugins: list[Plugin | LegacyPlugin] = []
        plugins.extend(self.load_builtin_plugins())
        plugins.extend(self.load_directory_plugins())
        plugins.extend(self.load_entry_point_plugins())
        return plugins

    def load_builtin_plugins(self) -> list[Plugin | LegacyPlugin]:
        """Load built-in plugins shipped with TechSpecter."""
        if not self._load_builtins:
            return []
        return self._load_plugins_from_package(BUILTIN_PACKAGE)

    def load_directory_plugins(self) -> list[Plugin | LegacyPlugin]:
        """Load plugins from configured external directories."""
        loaded: list[Plugin | LegacyPlugin] = []
        for directory in self._plugin_directories:
            if not directory.is_dir():
                logger.debug("Plugin directory does not exist: %s", directory)
                continue
            for module_name in discover_modules_in_directory(directory):
                module = import_module_from_directory(directory, module_name)
                if module is None:
                    continue
                plugin = extract_plugin_from_module(module)
                if plugin is None:
                    logger.warning(
                        "Plugin module '%s' does not export 'plugin' or 'create_plugin()'",
                        module_name,
                    )
                    continue
                loaded.append(self._coerce_plugin(plugin, source=str(directory)))
        return loaded

    def load_entry_point_plugins(self) -> list[Plugin | LegacyPlugin]:
        """Load plugins registered via Python entry points."""
        if not self._load_entry_points:
            return []

        loaded: list[Plugin | LegacyPlugin] = []
        for entry in _iter_entry_points(ENTRYPOINT_GROUP):
            try:
                plugin_factory = entry.load()
                plugin = plugin_factory() if callable(plugin_factory) else plugin_factory
                loaded.append(self._coerce_plugin(plugin, source=f"entry-point:{entry.name}"))
            except Exception as exc:
                logger.warning("Failed to load entry point plugin '%s': %s", entry.name, exc)
        return loaded

    def _load_plugins_from_package(self, package_name: str) -> list[Plugin | LegacyPlugin]:
        """Load plugins exported by submodules in a package."""
        from pkgutil import walk_packages

        loaded: list[Plugin | LegacyPlugin] = []
        try:
            package = importlib.import_module(package_name)
        except ImportError:
            return loaded

        plugin_paths = getattr(package, "__path__", None)
        if plugin_paths is None:
            plugin = getattr(package, "plugin", None)
            if plugin is not None:
                loaded.append(self._coerce_plugin(plugin, source=package_name))
            return loaded

        for module_info in walk_packages(plugin_paths, prefix=f"{package_name}."):
            if module_info.ispkg:
                continue
            try:
                module = importlib.import_module(module_info.name)
            except Exception as exc:
                logger.warning("Failed to import built-in plugin '%s': %s", module_info.name, exc)
                continue
            plugin = extract_plugin_from_module(module)
            if plugin is not None:
                loaded.append(self._coerce_plugin(plugin, source=module_info.name))
        return loaded

    def _coerce_plugin(self, plugin: object, *, source: str) -> Plugin | LegacyPlugin:
        """Validate that a loaded object is a plugin."""
        if isinstance(plugin, (Plugin, LegacyPlugin)):
            logger.info("Loaded plugin from %s", source)
            return plugin
        msg = f"Object loaded from {source} is not a Plugin instance."
        raise PluginLoadError(msg)


def _iter_entry_points(group: str) -> list[EntryPoint]:
    """Return entry points for a group across Python versions."""
    try:
        return list(entry_points(group=group))
    except TypeError:
        legacy = entry_points()
        selected = legacy.get(group, ())
        return list(cast("Iterable[EntryPoint]", selected))
