"""Public developer SDK for TechSpecter plugin authors."""

from techspecter.plugins.developer.decorators import hook, plugin, register_hooks
from techspecter.plugins.developer.diagnostics import (
    PluginDiagnosticsReport,
    diagnose_plugins,
    environment_diagnostics,
    registry_diagnostics,
)
from techspecter.plugins.developer.helpers import (
    compare_versions,
    configuration_enabled,
    inspect_metadata,
    is_compatible,
    plugin_identifier,
    python_supported,
    settings_from_mapping,
    validate_plugin,
)
from techspecter.plugins.developer.metadata_builder import MetadataBuilder, metadata_for
from techspecter.plugins.developer.types import (
    HookContext,
    HookHandler,
    LifecycleHandler,
    MetadataOverrides,
    PluginContext,
    PluginFactory,
    PluginInstance,
    PluginMetadata,
)
from techspecter.plugins.exceptions import (
    PluginCompatibilityError,
    PluginConfigurationError,
    PluginDependencyError,
    PluginError,
    PluginExecutionError,
    PluginLoadError,
    PluginNotFoundError,
    PluginRegistrationError,
    PluginValidationError,
)
from techspecter.plugins.interfaces import (
    AnalyzerPlugin,
    ExporterPlugin,
    LifecyclePlugin,
    Plugin,
    ReporterPlugin,
    RulePackPlugin,
)
from techspecter.plugins.metadata import PluginType
from techspecter.plugins.sdk import normalize_platforms, parse_version

__all__ = [
    "AnalyzerPlugin",
    "ExporterPlugin",
    "HookContext",
    "HookHandler",
    "LifecycleHandler",
    "LifecyclePlugin",
    "MetadataBuilder",
    "MetadataOverrides",
    "Plugin",
    "PluginCompatibilityError",
    "PluginConfigurationError",
    "PluginContext",
    "PluginDependencyError",
    "PluginDiagnosticsReport",
    "PluginError",
    "PluginExecutionError",
    "PluginFactory",
    "PluginInstance",
    "PluginLoadError",
    "PluginMetadata",
    "PluginNotFoundError",
    "PluginRegistrationError",
    "PluginType",
    "PluginValidationError",
    "ReporterPlugin",
    "RulePackPlugin",
    "compare_versions",
    "configuration_enabled",
    "diagnose_plugins",
    "environment_diagnostics",
    "hook",
    "inspect_metadata",
    "is_compatible",
    "metadata_for",
    "normalize_platforms",
    "parse_version",
    "plugin",
    "plugin_identifier",
    "python_supported",
    "registry_diagnostics",
    "register_hooks",
    "settings_from_mapping",
    "validate_plugin",
]
