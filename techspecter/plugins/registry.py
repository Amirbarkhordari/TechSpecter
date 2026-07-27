"""Plugin registry and discovery system."""

from __future__ import annotations

import builtins
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TypeVar

from techspecter.core.interfaces import Plugin as LegacyPlugin
from techspecter.core.interfaces import PluginMetadata as CorePluginMetadata
from techspecter.exceptions import PluginNotFoundError
from techspecter.plugins.interfaces import Plugin
from techspecter.plugins.metadata import PluginMetadata, PluginType
from techspecter.plugins.validator import PluginValidator

PluginT = TypeVar("PluginT", bound=LegacyPlugin)


def plugin_id(plugin: Plugin | LegacyPlugin) -> str:
    """Return the canonical identifier for a plugin instance."""
    if isinstance(plugin, Plugin):
        return plugin.plugin_metadata.id
    return plugin.metadata.name


@dataclass(frozen=True, slots=True)
class RegisteredPlugin:
    """Immutable registration record for a plugin."""

    plugin: Plugin | LegacyPlugin
    metadata: PluginMetadata | CorePluginMetadata


class PluginRegistry:
    """Central registry for TechSpecter plugins.

    Plugins register themselves by identifier and are retrieved at runtime without
    modifying core application code. This supports analyzers, reporters, exporters,
    and rule packs contributed through the plugin SDK.
    """

    def __init__(self, *, validator: PluginValidator | None = None) -> None:
        """Initialize an empty plugin registry."""
        self._plugins: dict[str, RegisteredPlugin] = {}
        self._validator = validator or PluginValidator()

    def register(self, plugin: Plugin | LegacyPlugin) -> None:
        """Register a plugin instance.

        Args:
            plugin: Plugin instance to register.

        Raises:
            ValueError: If a plugin with the same identifier is already registered.
        """
        identifier = plugin_id(plugin)
        if identifier in self._plugins:
            msg = f"Plugin '{identifier}' is already registered."
            raise ValueError(msg)

        report = self._validator.validate(
            plugin,
            registered_ids=set(self._plugins.keys()),
        )
        if not report.is_valid:
            msg = "; ".join(report.errors)
            raise ValueError(msg)

        metadata = self._snapshot_metadata(plugin)
        if isinstance(plugin, LegacyPlugin) and not isinstance(plugin, Plugin):
            plugin.setup()
        self._plugins[identifier] = RegisteredPlugin(plugin=plugin, metadata=metadata)

    def unregister(self, name: str) -> None:
        """Remove a plugin from the registry.

        Args:
            name: Unique plugin identifier.

        Raises:
            PluginNotFoundError: If no plugin with the given name exists.
        """
        record = self._plugins.pop(name, None)
        if record is None:
            msg = f"Plugin '{name}' not found."
            raise PluginNotFoundError(msg)
        plugin = record.plugin
        if isinstance(plugin, LegacyPlugin) and not isinstance(plugin, Plugin):
            plugin.teardown()

    def get(self, name: str) -> Plugin | LegacyPlugin:
        """Retrieve a registered plugin by name.

        Args:
            name: Unique plugin identifier.

        Returns:
            The registered plugin instance.

        Raises:
            PluginNotFoundError: If no plugin with the given name exists.
        """
        record = self._plugins.get(name)
        if record is None:
            msg = f"Plugin '{name}' not found."
            raise PluginNotFoundError(msg)
        return record.plugin

    def find(self, name: str) -> Plugin | LegacyPlugin | None:
        """Return a registered plugin or ``None`` when absent."""
        record = self._plugins.get(name)
        if record is None:
            return None
        return record.plugin

    def exists(self, name: str) -> bool:
        """Return whether a plugin identifier is registered."""
        return name in self._plugins

    def list(self) -> tuple[str, ...]:
        """Return immutable identifiers for all registered plugins."""
        return tuple(sorted(self._plugins.keys()))

    def list_plugins(self) -> builtins.list[str]:
        """Return names of all registered plugins.

        Returns:
            Sorted list of registered plugin names.
        """
        return list(self.list())

    def list_instances(self) -> tuple[Plugin | LegacyPlugin, ...]:
        """Return immutable plugin instances in registration order."""
        return tuple(record.plugin for record in self._plugins.values())

    def list_by_type(self, plugin_type: PluginType) -> tuple[str, ...]:
        """Return plugin identifiers filtered by plugin type."""
        matched: list[str] = []
        for identifier, record in self._plugins.items():
            metadata = record.metadata
            if isinstance(metadata, PluginMetadata) and metadata.plugin_type == plugin_type:
                matched.append(identifier)
        return tuple(sorted(matched))

    def metadata_view(self) -> Mapping[str, PluginMetadata | CorePluginMetadata]:
        """Return an immutable view of registered plugin metadata."""
        return MappingProxyType(
            {identifier: record.metadata for identifier, record in self._plugins.items()}
        )

    def clear(self) -> None:
        """Unregister and teardown all plugins."""
        for name in list(self._plugins.keys()):
            self.unregister(name)

    @staticmethod
    def _snapshot_metadata(plugin: Plugin | LegacyPlugin) -> PluginMetadata | CorePluginMetadata:
        """Capture immutable metadata at registration time."""
        if isinstance(plugin, Plugin):
            return plugin.plugin_metadata.frozen_copy()
        return plugin.metadata


registry = PluginRegistry()
