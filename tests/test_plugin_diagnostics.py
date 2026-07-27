"""Tests for plugin diagnostics."""

from __future__ import annotations

from unittest.mock import patch

from techspecter.plugins.config import PluginConfiguration
from techspecter.plugins.developer.diagnostics import (
    diagnose_plugins,
    environment_diagnostics,
    registry_diagnostics,
)
from techspecter.plugins.manager import PluginManager
from techspecter.plugins.validator import PluginValidationReport
from tests.plugin_fixtures import RecordingLifecyclePlugin


def test_environment_diagnostics_contains_versions() -> None:
    """Verify environment diagnostics include runtime details."""
    env = environment_diagnostics()
    assert env.techspecter_version
    assert env.python_version
    assert env.platform


def test_registry_diagnostics_reports_plugins() -> None:
    """Verify registry diagnostics include plugin types."""
    manager = PluginManager()
    manager.registry.register(RecordingLifecyclePlugin())
    report = registry_diagnostics(manager.registry)
    assert "sample-plugin" in report.registered_plugins
    assert report.plugin_types["sample-plugin"] == "lifecycle"
    manager.shutdown()


def test_diagnose_plugins_reports_disabled_warning() -> None:
    """Verify diagnostics report globally disabled plugin system."""
    manager = PluginManager()
    report = diagnose_plugins(
        manager=manager,
        configuration=PluginConfiguration(enabled=False),
    )
    assert any("globally disabled" in warning for warning in report.warnings)


def test_diagnose_plugins_collects_validation_issues() -> None:
    """Verify diagnostics include validation issues for registered plugins."""
    manager = PluginManager()
    manager.registry.register(RecordingLifecyclePlugin())
    invalid = PluginValidationReport(
        plugin_id="sample-plugin",
        is_valid=False,
        errors=["broken"],
    )
    with patch(
        "techspecter.plugins.developer.diagnostics.PluginValidator.validate", return_value=invalid
    ):
        report = diagnose_plugins(manager=manager, configuration=PluginConfiguration())
    assert report.issues == ["broken"]
    manager.shutdown()
