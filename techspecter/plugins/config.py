"""Plugin configuration models."""

from __future__ import annotations

from pydantic import Field

from techspecter.configuration.models import PluginsConfig
from techspecter.models.base import TechSpecterModel
from techspecter.plugins.context import PluginSettings


class PluginConfigEntry(TechSpecterModel):
    """Configuration for a single plugin."""

    enabled: bool = True
    settings: dict[str, object] = Field(default_factory=dict)

    def to_settings(self) -> PluginSettings:
        """Convert to runtime plugin settings."""
        return PluginSettings(enabled=self.enabled, values=dict(self.settings))


class PluginConfiguration(TechSpecterModel):
    """Top-level plugin configuration."""

    enabled: bool = True
    plugin_directories: list[str] = Field(default_factory=list)
    load_entry_points: bool = True
    disabled_plugins: list[str] = Field(default_factory=list)
    enabled_plugins: list[str] = Field(default_factory=list)
    plugins: dict[str, PluginConfigEntry] = Field(default_factory=dict)

    def is_plugin_enabled(self, plugin_id: str) -> bool:
        """Return whether a plugin is enabled."""
        if not self.enabled:
            return False
        if plugin_id in self.disabled_plugins:
            return False
        if self.enabled_plugins and plugin_id not in self.enabled_plugins:
            return False
        entry = self.plugins.get(plugin_id)
        if entry is None:
            return True
        return entry.enabled

    def settings_for(self, plugin_id: str) -> PluginSettings:
        """Return settings for a plugin."""
        entry = self.plugins.get(plugin_id)
        if entry is None:
            return PluginSettings()
        return entry.to_settings()

    @classmethod
    def from_plugins_config(cls, config: PluginsConfig) -> PluginConfiguration:
        """Build plugin configuration from the root configuration section."""
        return cls(
            enabled=config.enabled,
            plugin_directories=list(config.directories),
            load_entry_points=config.load_entry_points,
            disabled_plugins=list(config.disabled_plugins),
            enabled_plugins=list(config.enabled_plugins),
            plugins={
                plugin_id: PluginConfigEntry(
                    enabled=entry.enabled,
                    settings=dict(entry.settings),
                )
                for plugin_id, entry in config.plugins.items()
            },
        )
