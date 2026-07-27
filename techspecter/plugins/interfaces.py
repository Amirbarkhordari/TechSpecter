"""Plugin interface hierarchy."""

from __future__ import annotations

from abc import abstractmethod
from pathlib import Path

from techspecter.analysis.analyzers.base import Analyzer
from techspecter.core.context import ScanContext
from techspecter.core.interfaces import Plugin as CorePlugin
from techspecter.core.interfaces import PluginMetadata as CorePluginMetadata
from techspecter.core.interfaces import ScanResult
from techspecter.plugins.context import PluginContext
from techspecter.plugins.metadata import PluginMetadata, PluginType
from techspecter.reporting.engine import ReportEngine
from techspecter.reporting.exporters.base import BaseExporter


class Plugin(CorePlugin):
    """Base class for all TechSpecter extension plugins."""

    _initialized: bool = False
    _enabled: bool = True

    @property
    @abstractmethod
    def plugin_metadata(self) -> PluginMetadata:
        """Return rich plugin metadata."""

    @property
    def metadata(self) -> CorePluginMetadata:
        """Return legacy metadata for registry compatibility."""
        return self.plugin_metadata.to_core_metadata()

    @abstractmethod
    def execute(self, context: ScanContext) -> ScanResult:
        """Run the plugin against a scan context."""

    def initialize(self, context: PluginContext) -> None:
        """Initialize plugin resources."""

    def register(self, context: PluginContext) -> None:
        """Register plugin contributions."""

    def start(self, context: PluginContext) -> None:
        """Start the plugin after registration."""

    def enable(self, context: PluginContext) -> None:
        """Enable the plugin after it has been started."""

    def disable(self, context: PluginContext) -> None:
        """Disable the plugin without unloading it."""

    def shutdown(self, context: PluginContext) -> None:
        """Shutdown the plugin before cleanup."""

    def cleanup(self, context: PluginContext) -> None:
        """Release plugin resources."""

    def setup(self) -> None:
        """Legacy setup hook used by the basic registry."""
        return None

    def teardown(self) -> None:
        """Legacy teardown hook used by the basic registry."""
        return None

    @property
    def is_enabled(self) -> bool:
        """Return whether the plugin is currently enabled."""
        return self._enabled


class LifecyclePlugin(Plugin):
    """Plugin that participates in explicit lifecycle management."""

    def execute(self, context: ScanContext) -> ScanResult:
        """Lifecycle plugins do not execute scans directly."""
        return ScanResult(plugin_name=self.plugin_metadata.id, findings={})


class AnalyzerPlugin(Plugin):
    """Plugin that contributes passive analyzers."""

    def analyzers(self) -> list[Analyzer]:
        """Return analyzer implementations contributed by this plugin."""
        return []

    def execute(self, context: ScanContext) -> ScanResult:
        """Analyzer plugins expose analyzer resources."""
        return ScanResult(
            plugin_name=self.plugin_metadata.id,
            findings={"analyzers": [analyzer.metadata.id for analyzer in self.analyzers()]},
        )


class ReporterPlugin(Plugin):
    """Plugin that contributes report generation engines."""

    def report_engines(self) -> dict[str, ReportEngine]:
        """Return custom report engines keyed by identifier."""
        return {}

    def execute(self, context: ScanContext) -> ScanResult:
        """Reporter plugins expose report engine resources."""
        return ScanResult(
            plugin_name=self.plugin_metadata.id,
            findings={"reporters": list(self.report_engines().keys())},
        )


class ExporterPlugin(Plugin):
    """Plugin that contributes report exporters."""

    def exporters(self) -> dict[str, BaseExporter]:
        """Return custom report exporters keyed by format name."""
        return {}

    def execute(self, context: ScanContext) -> ScanResult:
        """Exporter plugins expose export formats."""
        return ScanResult(
            plugin_name=self.plugin_metadata.id,
            findings={"exporters": list(self.exporters().keys())},
        )


class RulePackPlugin(Plugin):
    """Plugin that contributes rule pack directories."""

    def rule_directories(self) -> list[Path]:
        """Return directories containing YAML or JSON rule definitions."""
        return []

    def execute(self, context: ScanContext) -> ScanResult:
        """Rule pack plugins expose rule directories."""
        return ScanResult(
            plugin_name=self.plugin_metadata.id,
            findings={"rule_directories": [str(path) for path in self.rule_directories()]},
        )


def plugin_type_for(plugin: Plugin) -> PluginType:
    """Return the declared plugin type for an SDK plugin instance."""
    return plugin.plugin_metadata.plugin_type
