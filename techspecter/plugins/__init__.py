"""Plugin registry and discovery system."""

from techspecter.plugins.config import PluginConfigEntry, PluginConfiguration
from techspecter.plugins.context import PluginContext, PluginLogger, PluginResources, PluginSettings
from techspecter.plugins.developer import (
    MetadataBuilder,
    diagnose_plugins,
    environment_diagnostics,
    hook,
    metadata_for,
    plugin,
    register_hooks,
    validate_plugin,
)
from techspecter.plugins.events import (
    AnalysisCompleted,
    AnalysisStarted,
    EventBus,
    ExportCompleted,
    PluginDisabled,
    PluginEnabled,
    PluginInitialized,
    PluginLoaded,
    PluginShutdown,
    ReportGenerated,
)
from techspecter.plugins.exceptions import (
    PluginCompatibilityError,
    PluginConfigurationError,
    PluginDependencyError,
    PluginExecutionError,
    PluginLoadError,
    PluginRegistrationError,
    PluginValidationError,
)
from techspecter.plugins.hooks import HookContext, HookName, HookRegistry
from techspecter.plugins.interfaces import (
    AnalyzerPlugin,
    ExporterPlugin,
    HookPlugin,
    LifecyclePlugin,
    Plugin,
    ReporterPlugin,
    RulePackPlugin,
    plugin_type_for,
)
from techspecter.plugins.lifecycle import PluginLifecycle
from techspecter.plugins.loader import PluginLoader
from techspecter.plugins.manager import PluginManager
from techspecter.plugins.metadata import PluginMetadata, PluginType
from techspecter.plugins.registry import PluginRegistry, plugin_id, registry
from techspecter.plugins.safety import safe_call, safe_call_or_raise
from techspecter.plugins.sdk import normalize_platforms, parse_version
from techspecter.plugins.services import PluginServices
from techspecter.plugins.validator import PluginValidationReport, PluginValidator

__all__ = [
    "AnalysisCompleted",
    "AnalysisStarted",
    "AnalyzerPlugin",
    "EventBus",
    "ExporterPlugin",
    "ExportCompleted",
    "HookContext",
    "HookName",
    "HookPlugin",
    "HookRegistry",
    "LifecyclePlugin",
    "MetadataBuilder",
    "Plugin",
    "PluginCompatibilityError",
    "PluginConfigurationError",
    "PluginConfigEntry",
    "PluginConfiguration",
    "PluginContext",
    "PluginDependencyError",
    "PluginDisabled",
    "PluginEnabled",
    "PluginExecutionError",
    "PluginInitialized",
    "PluginLifecycle",
    "PluginLoadError",
    "PluginLoaded",
    "PluginLoader",
    "PluginLogger",
    "PluginManager",
    "PluginMetadata",
    "PluginRegistrationError",
    "PluginRegistry",
    "PluginResources",
    "PluginServices",
    "PluginSettings",
    "PluginShutdown",
    "PluginType",
    "PluginValidationError",
    "PluginValidationReport",
    "PluginValidator",
    "ReportGenerated",
    "ReporterPlugin",
    "RulePackPlugin",
    "diagnose_plugins",
    "environment_diagnostics",
    "hook",
    "metadata_for",
    "normalize_platforms",
    "parse_version",
    "plugin",
    "plugin_id",
    "plugin_type_for",
    "register_hooks",
    "registry",
    "safe_call",
    "safe_call_or_raise",
    "validate_plugin",
]
