"""Helper utilities for plugin developers."""

from __future__ import annotations

from techspecter import __version__
from techspecter.core.interfaces import Plugin as LegacyPlugin
from techspecter.plugins.config import PluginConfiguration
from techspecter.plugins.context import PluginSettings
from techspecter.plugins.interfaces import Plugin
from techspecter.plugins.metadata import PluginMetadata
from techspecter.plugins.registry import plugin_id
from techspecter.plugins.sdk import (
    current_python_version,
    is_python_version_compatible,
    parse_version,
)
from techspecter.plugins.validator import PluginValidationReport, PluginValidator


def validate_plugin(
    plugin: Plugin | LegacyPlugin,
    *,
    core_version: str | None = None,
    registered_ids: set[str] | None = None,
    available_ids: set[str] | None = None,
) -> PluginValidationReport:
    """Validate a plugin instance."""
    return PluginValidator(core_version=core_version or __version__).validate(
        plugin,
        registered_ids=registered_ids,
        available_ids=available_ids,
    )


def inspect_metadata(plugin: Plugin | LegacyPlugin) -> PluginMetadata | None:
    """Return rich metadata for an SDK plugin."""
    if isinstance(plugin, Plugin):
        return plugin.plugin_metadata.frozen_copy()
    return None


def is_compatible(metadata: PluginMetadata, *, core_version: str | None = None) -> bool:
    """Return whether metadata is compatible with the active environment."""
    return metadata.is_core_compatible(
        core_version or __version__
    ) and metadata.is_python_compatible(current_python_version())


def settings_from_mapping(values: dict[str, object] | None = None) -> PluginSettings:
    """Build plugin settings from a mapping."""
    return PluginSettings(values=dict(values or {}))


def compare_versions(left: str, right: str) -> int:
    """Compare two semantic version strings."""
    left_parts = parse_version(left)
    right_parts = parse_version(right)
    if left_parts == right_parts:
        return 0
    return 1 if left_parts > right_parts else -1


def plugin_identifier(plugin: Plugin | LegacyPlugin) -> str:
    """Return the canonical plugin identifier."""
    return plugin_id(plugin)


def configuration_enabled(
    plugin_configuration: PluginConfiguration,
    plugin_identifier_value: str,
) -> bool:
    """Return whether a plugin is enabled in configuration."""
    return plugin_configuration.is_plugin_enabled(plugin_identifier_value)


def python_supported(minimum_python_version: str) -> bool:
    """Return whether the active Python version satisfies a minimum."""
    return is_python_version_compatible(minimum_python_version)
