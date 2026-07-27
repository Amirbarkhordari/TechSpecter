"""Plugin manager orchestrating loading, validation, and lifecycle."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from techspecter.analysis.analyzers.base import Analyzer
from techspecter.core.interfaces import Plugin as LegacyPlugin
from techspecter.plugins.config import PluginConfiguration
from techspecter.plugins.context import PluginContext, PluginLogger, PluginResources
from techspecter.plugins.interfaces import (
    AnalyzerPlugin,
    ExporterPlugin,
    Plugin,
    ReporterPlugin,
    RulePackPlugin,
)
from techspecter.plugins.lifecycle import PluginLifecycle
from techspecter.plugins.loader import PluginLoader
from techspecter.plugins.metadata import PluginMetadata
from techspecter.plugins.registry import PluginRegistry, plugin_id
from techspecter.plugins.validator import PluginValidator
from techspecter.reporting.engine import ReportEngine
from techspecter.reporting.exporters.base import BaseExporter

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class PluginManager:
    """Load, validate, and manage TechSpecter plugins."""

    configuration: PluginConfiguration = field(default_factory=PluginConfiguration)
    registry: PluginRegistry = field(default_factory=PluginRegistry)
    lifecycle: PluginLifecycle = field(default_factory=PluginLifecycle)
    validator: PluginValidator = field(default_factory=PluginValidator)
    loader: PluginLoader | None = None
    _contexts: dict[str, PluginContext] = field(default_factory=dict, init=False)

    def load_plugins(
        self,
        *,
        plugin_directories: list[str | Path] | None = None,
        load_entry_points: bool | None = None,
        load_builtins: bool = False,
    ) -> list[str]:
        """Load and register plugins from all configured sources."""
        directories = list(plugin_directories or self.configuration.plugin_directories)
        entry_points_enabled = (
            self.configuration.load_entry_points if load_entry_points is None else load_entry_points
        )
        self.loader = PluginLoader(
            plugin_directories=directories,
            load_entry_points=entry_points_enabled,
            load_builtins=load_builtins,
        )
        loaded_ids: list[str] = []
        candidates = self.loader.load_all()

        for candidate in candidates:
            identifier = plugin_id(candidate)
            if not self.configuration.is_plugin_enabled(identifier):
                logger.info("Plugin '%s' disabled by configuration", identifier)
                continue
            if self.registry.find(identifier) is not None:
                logger.warning("Ignoring duplicate plugin ID '%s'", identifier)
                continue

            report = self.validator.validate(
                candidate,
                registered_ids=set(self.registry.list_plugins()),
                available_ids={plugin_id(item) for item in candidates if item is not candidate},
            )
            if not report.is_valid:
                logger.warning(
                    "Plugin '%s' failed validation: %s",
                    identifier,
                    "; ".join(report.errors),
                )
                continue

            context = self._build_context(candidate)
            if isinstance(candidate, Plugin) and not self.lifecycle.safe_initialize(
                candidate, context
            ):
                continue

            try:
                self.registry.register(candidate)
            except ValueError:
                logger.warning("Plugin '%s' is already registered", identifier)
                continue

            self._contexts[identifier] = context
            loaded_ids.append(identifier)
            logger.info("Plugin loaded: %s", identifier)

        return loaded_ids

    def shutdown(self) -> None:
        """Shutdown all registered plugins."""
        for identifier in reversed(self.registry.list_plugins()):
            plugin = self.registry.find(identifier)
            context = self._contexts.get(identifier)
            if plugin is not None and context is not None and isinstance(plugin, Plugin):
                self.lifecycle.safe_shutdown(plugin, context)
            try:
                self.registry.unregister(identifier)
            except Exception as exc:
                logger.warning("Failed to unregister plugin '%s': %s", identifier, exc)
        self._contexts.clear()

    def collect_analyzers(self) -> list[Analyzer]:
        """Collect analyzers contributed by analyzer plugins."""
        analyzers: list[Analyzer] = []
        for plugin in self.registry.list_instances():
            if isinstance(plugin, AnalyzerPlugin):
                analyzers.extend(plugin.analyzers())
        return analyzers

    def collect_report_engines(self) -> dict[str, ReportEngine]:
        """Collect report engines contributed by reporter plugins."""
        engines: dict[str, ReportEngine] = {}
        for plugin in self.registry.list_instances():
            if isinstance(plugin, ReporterPlugin):
                engines.update(plugin.report_engines())
        return engines

    def collect_exporters(self) -> dict[str, BaseExporter]:
        """Collect exporters contributed by exporter plugins."""
        exporters: dict[str, BaseExporter] = {}
        for plugin in self.registry.list_instances():
            if isinstance(plugin, ExporterPlugin):
                exporters.update(plugin.exporters())
        return exporters

    def collect_rule_directories(self) -> list[Path]:
        """Collect rule directories contributed by rule pack plugins."""
        directories: list[Path] = []
        for plugin in self.registry.list_instances():
            if isinstance(plugin, RulePackPlugin):
                directories.extend(plugin.rule_directories())
        return directories

    def _build_context(self, plugin: Plugin | LegacyPlugin) -> PluginContext:
        """Build a plugin context for lifecycle methods."""
        if isinstance(plugin, Plugin):
            metadata = plugin.plugin_metadata
            settings = self.configuration.settings_for(metadata.id)
        else:
            metadata = PluginMetadataAdapter.from_legacy(plugin)
            settings = self.configuration.settings_for(metadata.id)

        return PluginContext(
            metadata=metadata,
            settings=settings,
            resources=PluginResources(),
            logger=PluginLogger(metadata.id),
        )


class PluginMetadataAdapter:
    """Adapter for legacy plugin metadata."""

    @staticmethod
    def from_legacy(plugin: LegacyPlugin) -> PluginMetadata:
        """Convert legacy plugin metadata to rich metadata."""
        legacy = plugin.metadata
        return PluginMetadata(
            id=legacy.name,
            name=legacy.name,
            version=legacy.version,
            description=legacy.description,
            author=legacy.author,
        )
