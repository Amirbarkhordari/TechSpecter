"""Tests for the plugin registry."""

from __future__ import annotations

import pytest

from techspecter.core.context import ScanContext
from techspecter.core.interfaces import Plugin as LegacyPlugin
from techspecter.core.interfaces import PluginMetadata as CorePluginMetadata
from techspecter.core.interfaces import ScanResult
from techspecter.exceptions import PluginNotFoundError
from techspecter.plugins.registry import PluginRegistry, plugin_id
from tests.plugin_fixtures import RecordingLifecyclePlugin, sample_metadata


class _LegacyStubPlugin(LegacyPlugin):
    """Minimal legacy plugin implementation for testing."""

    @property
    def metadata(self) -> CorePluginMetadata:
        return CorePluginMetadata(
            name="legacy-stub",
            version="0.0.1",
            description="Legacy test stub plugin",
        )

    def execute(self, context: ScanContext) -> ScanResult:
        return ScanResult(plugin_name="legacy-stub", findings={})


def test_register_and_get_plugin() -> None:
    """Verify plugins can be registered and retrieved by name."""
    reg = PluginRegistry()
    plugin = _LegacyStubPlugin()
    reg.register(plugin)
    assert reg.get("legacy-stub") is plugin
    assert reg.find("legacy-stub") is plugin
    assert reg.list_plugins() == ["legacy-stub"]
    assert reg.list_instances() == (plugin,)
    reg.unregister("legacy-stub")


def test_register_duplicate_raises() -> None:
    """Verify registering the same plugin twice raises ValueError."""
    reg = PluginRegistry()
    reg.register(_LegacyStubPlugin())
    with pytest.raises(ValueError, match="already registered"):
        reg.register(_LegacyStubPlugin())
    reg.clear()


def test_get_missing_plugin_raises() -> None:
    """Verify retrieving an unknown plugin raises PluginNotFoundError."""
    reg = PluginRegistry()
    with pytest.raises(PluginNotFoundError, match="not found"):
        reg.get("nonexistent")


def test_find_missing_returns_none() -> None:
    """Verify find returns None for unknown plugins."""
    reg = PluginRegistry()
    assert reg.find("missing") is None


def test_plugin_id_for_sdk_plugin() -> None:
    """Verify SDK plugins use metadata.id as identifier."""
    plugin = RecordingLifecyclePlugin(sample_metadata(id="sdk-id"))
    assert plugin_id(plugin) == "sdk-id"


def test_plugin_id_for_legacy_plugin() -> None:
    """Verify legacy plugins use metadata.name as identifier."""
    assert plugin_id(_LegacyStubPlugin()) == "legacy-stub"


def test_list_by_type_filters_plugins() -> None:
    """Verify list_by_type returns plugins matching the requested type."""
    from techspecter.plugins.interfaces import ExporterPlugin
    from techspecter.plugins.metadata import PluginType
    from techspecter.reporting.exporters.base import BaseExporter
    from techspecter.reporting.models import Report, ReportFormat

    class _Exporter(BaseExporter):
        format: ReportFormat = "json"

        def export(self, report: Report) -> str:
            return "{}"

    class _Plugin(ExporterPlugin):
        @property
        def plugin_metadata(self):
            return sample_metadata(id="exp-1", plugin_type=PluginType.EXPORTER)

        def exporters(self):
            return {"json": _Exporter()}

    reg = PluginRegistry()
    reg.register(_Plugin())
    reg.register(RecordingLifecyclePlugin(sample_metadata(id="life-1")))
    assert reg.list_by_type(PluginType.EXPORTER) == ("exp-1",)
    assert reg.list_by_type(PluginType.LIFECYCLE) == ("life-1",)
    reg.clear()


def test_metadata_view_is_immutable() -> None:
    """Verify metadata_view returns an immutable mapping."""
    reg = PluginRegistry()
    plugin = RecordingLifecyclePlugin()
    reg.register(plugin)
    view = reg.metadata_view()
    assert view["sample-plugin"].name == "Sample Plugin"
    reg.clear()
