"""Diagnostics utilities for plugin developers."""

from __future__ import annotations

import platform
import sys
from dataclasses import dataclass, field

from techspecter import __version__
from techspecter.plugins.config import PluginConfiguration
from techspecter.plugins.manager import PluginManager
from techspecter.plugins.registry import PluginRegistry
from techspecter.plugins.sdk import current_python_version
from techspecter.plugins.validator import PluginValidator


@dataclass(slots=True)
class EnvironmentDiagnostics:
    """Runtime environment diagnostics."""

    techspecter_version: str
    python_version: str
    platform: str
    implementation: str


@dataclass(slots=True)
class RegistryDiagnostics:
    """Plugin registry diagnostics."""

    registered_plugins: tuple[str, ...] = field(default_factory=tuple)
    plugin_types: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class PluginDiagnosticsReport:
    """Combined plugin diagnostics report."""

    environment: EnvironmentDiagnostics
    registry: RegistryDiagnostics
    configuration: PluginConfiguration
    issues: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def environment_diagnostics() -> EnvironmentDiagnostics:
    """Collect environment diagnostics."""
    return EnvironmentDiagnostics(
        techspecter_version=__version__,
        python_version=current_python_version(),
        platform=sys.platform,
        implementation=platform.python_implementation(),
    )


def registry_diagnostics(registry: PluginRegistry) -> RegistryDiagnostics:
    """Collect registry diagnostics."""
    plugin_types: dict[str, str] = {}
    for identifier, metadata in registry.metadata_view().items():
        plugin_type = getattr(metadata, "plugin_type", "legacy")
        if hasattr(plugin_type, "value"):
            plugin_types[identifier] = plugin_type.value
        else:
            plugin_types[identifier] = str(plugin_type)
    return RegistryDiagnostics(
        registered_plugins=registry.list(),
        plugin_types=plugin_types,
    )


def diagnose_plugins(
    *,
    manager: PluginManager,
    configuration: PluginConfiguration,
) -> PluginDiagnosticsReport:
    """Run plugin diagnostics and return a structured report."""
    report = PluginDiagnosticsReport(
        environment=environment_diagnostics(),
        registry=registry_diagnostics(manager.registry),
        configuration=configuration,
    )
    validator = PluginValidator()
    for identifier in manager.registry.list():
        plugin = manager.registry.get(identifier)
        validation = validator.validate(plugin, registered_ids=set(manager.registry.list()))
        if not validation.is_valid:
            report.issues.extend(validation.errors)
        report.warnings.extend(validation.warnings)
    if not configuration.enabled:
        report.warnings.append("Plugin system is globally disabled.")
    return report
