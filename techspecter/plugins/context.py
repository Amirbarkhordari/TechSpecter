"""Plugin execution context and developer SDK helpers."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from techspecter.plugins.metadata import PluginMetadata

if TYPE_CHECKING:
    from techspecter.plugins.services import PluginServices


@dataclass(slots=True)
class PluginSettings:
    """Validated plugin configuration values."""

    enabled: bool = True
    values: dict[str, object] = field(default_factory=dict)

    def get(self, key: str, default: object | None = None) -> object | None:
        """Return a configuration value."""
        return self.values.get(key, default)


@dataclass(slots=True)
class PluginResources:
    """Resource paths exposed to plugins."""

    plugin_root: Path | None = None
    rule_directories: list[Path] = field(default_factory=list)
    data_directory: Path | None = None


class PluginLogger:
    """Structured logger wrapper for plugin authors."""

    def __init__(self, plugin_id: str) -> None:
        """Initialize a plugin-scoped logger."""
        self._logger = logging.getLogger(f"techspecter.plugins.{plugin_id}")

    def debug(self, message: str, *args: object) -> None:
        """Log a debug message."""
        self._logger.debug(message, *args)

    def info(self, message: str, *args: object) -> None:
        """Log an info message."""
        self._logger.info(message, *args)

    def warning(self, message: str, *args: object) -> None:
        """Log a warning message."""
        self._logger.warning(message, *args)

    def error(self, message: str, *args: object) -> None:
        """Log an error message."""
        self._logger.error(message, *args)


@dataclass(slots=True)
class PluginContext:
    """Shared context passed to plugin lifecycle methods."""

    metadata: PluginMetadata
    settings: PluginSettings
    resources: PluginResources
    logger: PluginLogger
    data: dict[str, object] = field(default_factory=dict)
    services: PluginServices | None = None

    @property
    def plugin_id(self) -> str:
        """Return the plugin identifier."""
        return self.metadata.id
