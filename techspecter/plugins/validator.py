"""Plugin validation utilities."""

from __future__ import annotations

from dataclasses import dataclass, field

from techspecter import __version__
from techspecter.core.interfaces import Plugin as LegacyPlugin
from techspecter.plugins.exceptions import PluginValidationError
from techspecter.plugins.interfaces import (
    AnalyzerPlugin,
    ExporterPlugin,
    Plugin,
    ReporterPlugin,
    RulePackPlugin,
)
from techspecter.plugins.metadata import PluginMetadata, PluginType
from techspecter.plugins.sdk import current_python_version


@dataclass(slots=True)
class PluginValidationReport:
    """Validation results for a plugin."""

    plugin_id: str | None
    is_valid: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class PluginValidator:
    """Validate plugin metadata, interfaces, and compatibility."""

    _TYPE_REQUIRED_METHODS: dict[PluginType, tuple[str, ...]] = {
        PluginType.ANALYZER: ("analyzers",),
        PluginType.REPORTER: ("report_engines",),
        PluginType.EXPORTER: ("exporters",),
        PluginType.RULE_PACK: ("rule_directories",),
    }

    def __init__(self, core_version: str | None = None) -> None:
        """Initialize the validator."""
        self._core_version = core_version or __version__

    def validate(
        self,
        plugin: Plugin | LegacyPlugin,
        *,
        registered_ids: set[str] | None = None,
        available_ids: set[str] | None = None,
    ) -> PluginValidationReport:
        """Validate a plugin instance."""
        report = PluginValidationReport(plugin_id=None)

        if isinstance(plugin, Plugin):
            metadata = plugin.plugin_metadata
            report.plugin_id = metadata.id
            self._validate_metadata(metadata, report)
            self._validate_compatibility(metadata, report)
            self._validate_plugin_type(plugin, metadata, report)
            self._validate_dependencies(metadata, available_ids or set(), report)
        else:
            legacy_metadata = plugin.metadata
            report.plugin_id = legacy_metadata.name
            if not legacy_metadata.name.strip():
                report.errors.append("Plugin name must not be empty.")
            if not legacy_metadata.version.strip():
                report.errors.append("Plugin version must not be empty.")

        if registered_ids and report.plugin_id and report.plugin_id in registered_ids:
            report.errors.append(f"Duplicate plugin ID '{report.plugin_id}'.")

        if not hasattr(plugin, "execute"):
            report.errors.append("Plugin must implement execute().")

        report.is_valid = not report.errors
        return report

    def validate_or_raise(
        self,
        plugin: Plugin | LegacyPlugin,
        *,
        registered_ids: set[str] | None = None,
        available_ids: set[str] | None = None,
    ) -> PluginValidationReport:
        """Validate a plugin and raise when invalid."""
        report = self.validate(
            plugin,
            registered_ids=registered_ids,
            available_ids=available_ids,
        )
        if not report.is_valid:
            message = "; ".join(report.errors)
            raise PluginValidationError(message)
        return report

    def _validate_metadata(self, metadata: PluginMetadata, report: PluginValidationReport) -> None:
        """Validate rich plugin metadata."""
        if metadata.id != metadata.id.lower().replace(" ", "-"):
            report.warnings.append("Plugin IDs should use lowercase kebab-case.")

    def _validate_compatibility(
        self,
        metadata: PluginMetadata,
        report: PluginValidationReport,
    ) -> None:
        """Validate platform, core, and Python version compatibility."""
        if not metadata.is_platform_supported():
            report.errors.append("Plugin does not support the current platform.")
        if not metadata.is_core_compatible(self._core_version):
            report.errors.append(
                f"Plugin requires core version >= {metadata.minimum_core_version}."
            )
        if not metadata.is_python_compatible(current_python_version()):
            report.errors.append(f"Plugin requires Python >= {metadata.minimum_python_version}.")

    def _validate_plugin_type(
        self,
        plugin: Plugin,
        metadata: PluginMetadata,
        report: PluginValidationReport,
    ) -> None:
        """Validate that the plugin implements required methods for its type."""
        required = self._TYPE_REQUIRED_METHODS.get(metadata.plugin_type, ())
        for method_name in required:
            if not hasattr(plugin, method_name):
                report.errors.append(
                    f"Plugin type '{metadata.plugin_type.value}' requires {method_name}()."
                )

        type_checks: dict[PluginType, type[object]] = {
            PluginType.ANALYZER: AnalyzerPlugin,
            PluginType.REPORTER: ReporterPlugin,
            PluginType.EXPORTER: ExporterPlugin,
            PluginType.RULE_PACK: RulePackPlugin,
        }
        expected_base = type_checks.get(metadata.plugin_type)
        if expected_base is not None and not isinstance(plugin, expected_base):
            report.warnings.append(
                f"Plugin declares type '{metadata.plugin_type.value}' "
                f"but does not inherit from {expected_base.__name__}."
            )

    def _validate_dependencies(
        self,
        metadata: PluginMetadata,
        available_ids: set[str],
        report: PluginValidationReport,
    ) -> None:
        """Validate declared plugin dependencies."""
        missing = [dep for dep in metadata.dependencies if dep not in available_ids]
        if missing:
            report.errors.append(f"Missing plugin dependencies: {', '.join(missing)}")
