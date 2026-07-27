"""Plugin registry and discovery system."""

from techspecter.plugins.config import PluginConfigEntry, PluginConfiguration
from techspecter.plugins.context import PluginContext, PluginLogger, PluginResources, PluginSettings
from techspecter.plugins.exceptions import (
    PluginCompatibilityError,
    PluginConfigurationError,
    PluginDependencyError,
    PluginLoadError,
    PluginValidationError,
)
from techspecter.plugins.interfaces import (
    AnalyzerPlugin,
    ExporterPlugin,
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
from techspecter.plugins.sdk import normalize_platforms, parse_version
from techspecter.plugins.validator import PluginValidationReport, PluginValidator

__all__ = [
    "AnalyzerPlugin",
    "ExporterPlugin",
    "LifecyclePlugin",
    "Plugin",
    "PluginCompatibilityError",
    "PluginConfigurationError",
    "PluginConfigEntry",
    "PluginConfiguration",
    "PluginContext",
    "PluginDependencyError",
    "PluginLifecycle",
    "PluginLoadError",
    "PluginLoader",
    "PluginLogger",
    "PluginManager",
    "PluginMetadata",
    "PluginRegistry",
    "PluginResources",
    "PluginSettings",
    "PluginType",
    "PluginValidationError",
    "PluginValidationReport",
    "PluginValidator",
    "ReporterPlugin",
    "RulePackPlugin",
    "normalize_platforms",
    "parse_version",
    "plugin_id",
    "plugin_type_for",
    "registry",
]
