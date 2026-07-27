"""Metadata builder utilities for plugin developers."""

from __future__ import annotations

from techspecter import __version__
from techspecter.plugins.metadata import PluginMetadata, PluginType
from techspecter.plugins.sdk import current_python_version


class MetadataBuilder:
    """Fluent builder for plugin metadata."""

    def __init__(self, plugin_id: str, name: str) -> None:
        """Initialize a metadata builder."""
        self._data: dict[str, object] = {
            "id": plugin_id,
            "name": name,
            "version": "1.0.0",
            "description": name,
            "plugin_type": PluginType.LIFECYCLE,
            "minimum_core_version": "0.7.0",
            "minimum_python_version": current_python_version(),
        }

    def version(self, value: str) -> MetadataBuilder:
        """Set the plugin version."""
        self._data["version"] = value
        return self

    def description(self, value: str) -> MetadataBuilder:
        """Set the plugin description."""
        self._data["description"] = value
        return self

    def author(self, value: str) -> MetadataBuilder:
        """Set the plugin author."""
        self._data["author"] = value
        return self

    def homepage(self, value: str) -> MetadataBuilder:
        """Set the plugin homepage."""
        self._data["homepage"] = value
        return self

    def license(self, value: str) -> MetadataBuilder:
        """Set the plugin license."""
        self._data["license"] = value
        return self

    def plugin_type(self, value: PluginType) -> MetadataBuilder:
        """Set the plugin type."""
        self._data["plugin_type"] = value
        return self

    def minimum_core_version(self, value: str) -> MetadataBuilder:
        """Set the minimum TechSpecter version."""
        self._data["minimum_core_version"] = value
        return self

    def minimum_python_version(self, value: str) -> MetadataBuilder:
        """Set the minimum Python version."""
        self._data["minimum_python_version"] = value
        return self

    def tags(self, *values: str) -> MetadataBuilder:
        """Set plugin tags."""
        self._data["tags"] = list(values)
        return self

    def dependencies(self, *values: str) -> MetadataBuilder:
        """Set plugin dependencies."""
        self._data["dependencies"] = list(values)
        return self

    def build(self) -> PluginMetadata:
        """Build immutable plugin metadata."""
        metadata = PluginMetadata.model_validate(self._data)
        return metadata.model_copy(deep=True)


def metadata_for(
    plugin_id: str,
    name: str,
    *,
    plugin_type: PluginType = PluginType.LIFECYCLE,
    version: str = "1.0.0",
    description: str | None = None,
) -> PluginMetadata:
    """Create plugin metadata with sensible defaults."""
    return (
        MetadataBuilder(plugin_id, name)
        .version(version)
        .description(description or name)
        .plugin_type(plugin_type)
        .minimum_core_version(__version__)
        .build()
    )
