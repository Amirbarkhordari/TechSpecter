"""Tests for developer SDK package."""

from __future__ import annotations

from techspecter.plugins.developer import (
    MetadataBuilder,
    compare_versions,
    hook,
    inspect_metadata,
    is_compatible,
    metadata_for,
    plugin,
    validate_plugin,
)
from techspecter.plugins.hooks import HookName
from techspecter.plugins.interfaces import LifecyclePlugin
from techspecter.plugins.metadata import PluginType
from tests.plugin_fixtures import RecordingLifecyclePlugin, sample_metadata


def test_metadata_builder_creates_metadata() -> None:
    """Verify metadata builder produces valid metadata."""
    metadata = (
        MetadataBuilder("demo", "Demo Plugin")
        .version("2.0.0")
        .plugin_type(PluginType.ANALYZER)
        .author("Author")
        .build()
    )
    assert metadata.id == "demo"
    assert metadata.version == "2.0.0"
    assert metadata.plugin_type == PluginType.ANALYZER


def test_metadata_for_helper() -> None:
    """Verify metadata_for creates metadata with defaults."""
    metadata = metadata_for("demo", "Demo", plugin_type=PluginType.REPORTER)
    assert metadata.plugin_type == PluginType.REPORTER


def test_validate_plugin_helper() -> None:
    """Verify validate_plugin helper wraps validator."""
    report = validate_plugin(RecordingLifecyclePlugin())
    assert report.is_valid


def test_inspect_metadata_returns_copy() -> None:
    """Verify inspect_metadata returns rich metadata."""
    plugin = RecordingLifecyclePlugin()
    metadata = inspect_metadata(plugin)
    assert metadata is not None
    assert metadata.id == "sample-plugin"


def test_is_compatible_helper() -> None:
    """Verify compatibility helper."""
    metadata = sample_metadata(minimum_core_version="0.1.0")
    assert is_compatible(metadata, core_version="0.7.0")


def test_compare_versions_helper() -> None:
    """Verify version comparison helper."""
    assert compare_versions("1.0.0", "1.0.0") == 0
    assert compare_versions("1.1.0", "1.0.0") == 1


@plugin("decorated-plugin", plugin_type=PluginType.LIFECYCLE)
class _DecoratedPlugin(LifecyclePlugin):
    def execute(self, context):
        from techspecter.core.interfaces import ScanResult

        return ScanResult(plugin_name="decorated-plugin", findings={})


def test_plugin_decorator_attaches_metadata() -> None:
    """Verify plugin decorator attaches default metadata."""
    plugin_instance = _DecoratedPlugin()
    assert plugin_instance.plugin_metadata.id == "decorated-plugin"


def test_hook_decorator_marks_callback() -> None:
    """Verify hook decorator stores hook metadata."""

    @hook(HookName.AFTER_ANALYSIS, plugin_id="demo")
    def callback(context: object) -> None:
        return None

    assert callback._hook_name == HookName.AFTER_ANALYSIS
    assert callback._hook_plugin_id == "demo"


def test_register_hooks_helper() -> None:
    """Verify register_hooks registers decorated callbacks."""
    from techspecter.plugins.developer.decorators import register_hooks
    from techspecter.plugins.hooks import HookRegistry

    @hook(HookName.BEFORE_DISCOVERY, plugin_id="demo")
    def callback(context: object) -> None:
        return None

    registry = HookRegistry()
    plugin_instance = RecordingLifecyclePlugin()
    register_hooks(plugin_instance, registry, [callback])
    assert len(registry.list_hooks(HookName.BEFORE_DISCOVERY)) == 1


def test_metadata_builder_fluent_setters() -> None:
    """Verify metadata builder setter methods."""
    metadata = (
        MetadataBuilder("full", "Full Plugin")
        .description("desc")
        .homepage("https://example.com")
        .license("MIT")
        .minimum_core_version("0.7.0")
        .minimum_python_version("3.11")
        .tags("demo")
        .dependencies("other")
        .build()
    )
    assert metadata.homepage == "https://example.com"
    assert metadata.dependencies == ["other"]
