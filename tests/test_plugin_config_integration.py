"""Tests for plugin configuration integration."""

from __future__ import annotations

from techspecter.configuration.models import PluginEntryConfig, PluginsConfig
from techspecter.plugins.config import PluginConfiguration


def test_plugins_config_is_plugin_enabled() -> None:
    """Verify root configuration plugin enablement checks."""
    config = PluginsConfig(disabled_plugins=["blocked"])
    assert not config.is_plugin_enabled("blocked")
    assert config.is_plugin_enabled("allowed")


def test_plugins_config_enabled_plugins_whitelist() -> None:
    """Verify enabled_plugins acts as a whitelist when non-empty."""
    config = PluginsConfig(enabled_plugins=["allowed"])
    assert config.is_plugin_enabled("allowed")
    assert not config.is_plugin_enabled("other")


def test_from_plugins_config_maps_directories() -> None:
    """Verify PluginConfiguration maps the root plugins section."""
    root = PluginsConfig(
        enabled=True,
        directories=["/plugins"],
        load_entry_points=False,
        disabled_plugins=["legacy"],
        plugins={
            "custom": PluginEntryConfig(
                enabled=True,
                settings={"mode": "fast"},
            ),
        },
    )
    plugin_config = PluginConfiguration.from_plugins_config(root)
    assert plugin_config.plugin_directories == ["/plugins"]
    assert plugin_config.load_entry_points is False
    assert plugin_config.disabled_plugins == ["legacy"]
    assert plugin_config.settings_for("custom").get("mode") == "fast"
