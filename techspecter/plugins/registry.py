"""Plugin registry and discovery system."""

from __future__ import annotations

from typing import TypeVar

from techspecter.core.interfaces import Plugin
from techspecter.exceptions import PluginNotFoundError

PluginT = TypeVar("PluginT", bound=Plugin)


class PluginRegistry:
    """Central registry for TechSpecter plugins.

    Plugins register themselves by name and are retrieved at runtime without
    modifying core application code. This supports future modules such as
    JavaScript Discovery, CVE Intelligence, and Secret Discovery.
    """

    def __init__(self) -> None:
        """Initialize an empty plugin registry."""
        self._plugins: dict[str, Plugin] = {}

    def register(self, plugin: Plugin) -> None:
        """Register a plugin instance.

        Args:
            plugin: Plugin instance to register.

        Raises:
            ValueError: If a plugin with the same name is already registered.
        """
        name = plugin.metadata.name
        if name in self._plugins:
            msg = f"Plugin '{name}' is already registered."
            raise ValueError(msg)
        plugin.setup()
        self._plugins[name] = plugin

    def unregister(self, name: str) -> None:
        """Remove a plugin from the registry.

        Args:
            name: Unique plugin identifier.

        Raises:
            PluginNotFoundError: If no plugin with the given name exists.
        """
        plugin = self._plugins.pop(name, None)
        if plugin is None:
            msg = f"Plugin '{name}' not found."
            raise PluginNotFoundError(msg)
        plugin.teardown()

    def get(self, name: str) -> Plugin:
        """Retrieve a registered plugin by name.

        Args:
            name: Unique plugin identifier.

        Returns:
            The registered plugin instance.

        Raises:
            PluginNotFoundError: If no plugin with the given name exists.
        """
        plugin = self._plugins.get(name)
        if plugin is None:
            msg = f"Plugin '{name}' not found."
            raise PluginNotFoundError(msg)
        return plugin

    def list_plugins(self) -> list[str]:
        """Return names of all registered plugins.

        Returns:
            Sorted list of registered plugin names.
        """
        return sorted(self._plugins.keys())

    def clear(self) -> None:
        """Unregister and teardown all plugins."""
        for name in list(self._plugins.keys()):
            self.unregister(name)


registry = PluginRegistry()
