"""Tests for plugin configuration."""

from __future__ import annotations

from techspecter.plugins.config import PluginConfigEntry, PluginConfiguration


def test_plugin_enabled_by_default() -> None:
    """Verify plugins are enabled unless explicitly disabled."""
    config = PluginConfiguration()
    assert config.is_plugin_enabled("any-plugin")


def test_global_disable() -> None:
    """Verify global plugin disable flag."""
    config = PluginConfiguration(enabled=False)
    assert not config.is_plugin_enabled("any-plugin")


def test_disabled_plugins_list() -> None:
    """Verify disabled_plugins list disables specific plugins."""
    config = PluginConfiguration(disabled_plugins=["blocked"])
    assert not config.is_plugin_enabled("blocked")
    assert config.is_plugin_enabled("allowed")


def test_per_plugin_enable_flag() -> None:
    """Verify per-plugin enabled flag overrides defaults."""
    config = PluginConfiguration(
        plugins={"custom": PluginConfigEntry(enabled=False)},
    )
    assert not config.is_plugin_enabled("custom")


def test_plugin_settings() -> None:
    """Verify plugin settings are exposed through configuration."""
    config = PluginConfiguration(
        plugins={
            "custom": PluginConfigEntry(
                enabled=True,
                settings={"timeout": 30, "mode": "fast"},
            ),
        },
    )
    settings = config.settings_for("custom")
    assert settings.enabled is True
    assert settings.get("timeout") == 30
    assert settings.get("mode") == "fast"


def test_default_settings_for_unknown_plugin() -> None:
    """Verify unknown plugins receive default settings."""
    config = PluginConfiguration()
    settings = config.settings_for("unknown")
    assert settings.enabled is True
    assert settings.values == {}
