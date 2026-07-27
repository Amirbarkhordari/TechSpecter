"""Tests for plugin validation."""

from __future__ import annotations

import pytest

from techspecter.core.context import ScanContext
from techspecter.core.interfaces import Plugin as LegacyPlugin
from techspecter.core.interfaces import PluginMetadata as CorePluginMetadata
from techspecter.core.interfaces import ScanResult
from techspecter.plugins.exceptions import PluginValidationError
from techspecter.plugins.validator import PluginValidator
from tests.plugin_fixtures import RecordingLifecyclePlugin, sample_metadata


class _LegacyStubPlugin(LegacyPlugin):
    """Legacy plugin for validation tests."""

    @property
    def metadata(self) -> CorePluginMetadata:
        return CorePluginMetadata(
            name="legacy",
            version="1.0.0",
            description="Legacy plugin",
        )

    def execute(self, context: ScanContext) -> ScanResult:
        return ScanResult(plugin_name="legacy", findings={})


def test_validate_sdk_plugin_success() -> None:
    """Verify valid SDK plugins pass validation."""
    plugin = RecordingLifecyclePlugin()
    report = PluginValidator(core_version="0.5.0").validate(plugin)
    assert report.is_valid
    assert report.plugin_id == "sample-plugin"


def test_validate_duplicate_id_fails() -> None:
    """Verify duplicate plugin IDs are rejected."""
    plugin = RecordingLifecyclePlugin()
    report = PluginValidator().validate(plugin, registered_ids={"sample-plugin"})
    assert not report.is_valid
    assert any("Duplicate" in error for error in report.errors)


def test_validate_incompatible_core_version() -> None:
    """Verify incompatible core versions fail validation."""
    plugin = RecordingLifecyclePlugin(
        sample_metadata(minimum_core_version="99.0.0"),
    )
    report = PluginValidator(core_version="0.5.0").validate(plugin)
    assert not report.is_valid
    assert any("core version" in error for error in report.errors)


def test_validate_missing_dependencies() -> None:
    """Verify missing dependencies fail validation."""
    plugin = RecordingLifecyclePlugin(sample_metadata(dependencies=["other-plugin"]))
    report = PluginValidator().validate(plugin, available_ids={"sample-plugin"})
    assert not report.is_valid
    assert any("dependencies" in error for error in report.errors)


def test_validate_legacy_plugin() -> None:
    """Verify legacy plugins can be validated."""
    report = PluginValidator().validate(_LegacyStubPlugin())
    assert report.is_valid
    assert report.plugin_id == "legacy"


def test_validate_or_raise() -> None:
    """Verify validate_or_raise raises PluginValidationError."""
    plugin = RecordingLifecyclePlugin(
        sample_metadata(minimum_core_version="99.0.0"),
    )
    with pytest.raises(PluginValidationError):
        PluginValidator(core_version="0.5.0").validate_or_raise(plugin)
