"""Plugin-specific exceptions."""

from __future__ import annotations

from techspecter.exceptions import PluginError, PluginNotFoundError

__all__ = [
    "PluginCompatibilityError",
    "PluginConfigurationError",
    "PluginDependencyError",
    "PluginError",
    "PluginLoadError",
    "PluginNotFoundError",
    "PluginValidationError",
]


class PluginLoadError(PluginError):
    """Raised when a plugin cannot be loaded."""


class PluginValidationError(PluginError):
    """Raised when plugin metadata or interfaces are invalid."""


class PluginCompatibilityError(PluginError):
    """Raised when a plugin is incompatible with the current core version."""


class PluginConfigurationError(PluginError):
    """Raised when plugin configuration is invalid."""


class PluginDependencyError(PluginError):
    """Raised when plugin dependencies cannot be satisfied."""
