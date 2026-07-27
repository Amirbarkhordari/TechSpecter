"""Shared fixtures for plugin SDK tests."""

from __future__ import annotations

from pathlib import Path

from techspecter.core.context import ScanContext
from techspecter.core.interfaces import ScanResult
from techspecter.plugins.context import PluginContext
from techspecter.plugins.interfaces import LifecyclePlugin
from techspecter.plugins.metadata import PluginMetadata, PluginType


def sample_metadata(**overrides: object) -> PluginMetadata:
    """Build sample plugin metadata with optional overrides."""
    data: dict[str, object] = {
        "id": "sample-plugin",
        "name": "Sample Plugin",
        "version": "1.0.0",
        "description": "Sample plugin for tests",
        "plugin_type": PluginType.LIFECYCLE,
    }
    data.update(overrides)
    return PluginMetadata.model_validate(data)


class RecordingLifecyclePlugin(LifecyclePlugin):
    """Lifecycle plugin that records lifecycle method calls."""

    def __init__(self, metadata: PluginMetadata | None = None) -> None:
        """Initialize with optional metadata."""
        self._metadata = metadata or sample_metadata()
        self.calls: list[str] = []

    @property
    def plugin_metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self._metadata

    def initialize(self, context: PluginContext) -> None:
        """Record initialize call."""
        self.calls.append("initialize")

    def register(self, context: PluginContext) -> None:
        """Record register call."""
        self.calls.append("register")

    def start(self, context: PluginContext) -> None:
        """Record start call."""
        self.calls.append("start")

    def enable(self, context: PluginContext) -> None:
        """Record enable call."""
        self.calls.append("enable")

    def disable(self, context: PluginContext) -> None:
        """Record disable call."""
        self.calls.append("disable")

    def shutdown(self, context: PluginContext) -> None:
        """Record shutdown call."""
        self.calls.append("shutdown")

    def cleanup(self, context: PluginContext) -> None:
        """Record cleanup call."""
        self.calls.append("cleanup")

    def execute(self, context: ScanContext) -> ScanResult:
        """Return an empty scan result."""
        return ScanResult(plugin_name=self.plugin_metadata.id, findings={})


def write_directory_plugin(directory: Path, *, plugin_id: str = "dir-plugin") -> None:
    """Write a minimal plugin module to a directory."""
    source = f"""
from techspecter.plugins.interfaces import LifecyclePlugin
from techspecter.plugins.metadata import PluginMetadata, PluginType

class _DirPlugin(LifecyclePlugin):
    @property
    def plugin_metadata(self):
        return PluginMetadata(
            id="{plugin_id}",
            name="Directory Plugin",
            version="1.0.0",
            description="Loaded from directory",
            plugin_type=PluginType.LIFECYCLE,
        )

plugin = _DirPlugin()
"""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "sample_plugin.py").write_text(source.strip() + "\n", encoding="utf-8")
