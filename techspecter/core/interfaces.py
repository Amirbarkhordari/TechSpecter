"""Abstract interfaces for extensible plugin architecture."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from techspecter.core.context import ScanContext


@dataclass(frozen=True, slots=True)
class PluginMetadata:
    """Descriptive metadata for a registered plugin.

    Attributes:
        name: Unique plugin identifier.
        version: Semantic version string of the plugin.
        description: Human-readable description of plugin capabilities.
        author: Optional plugin author name.
    """

    name: str
    version: str
    description: str
    author: str | None = None


@dataclass(slots=True)
class ScanResult:
    """Standardized result container returned by plugins and pipeline stages.

    Attributes:
        plugin_name: Name of the plugin or stage that produced this result.
        findings: Structured findings keyed by category.
        errors: Non-fatal errors encountered during execution.
    """

    plugin_name: str
    findings: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


class Plugin(ABC):
    """Base class for all TechSpecter plugins.

    Subclasses implement domain-specific logic (crawling, detection, reporting)
    without modifying the application core. Plugins are discovered and invoked
    through the plugin registry.
    """

    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Return descriptive metadata for this plugin."""

    @abstractmethod
    def execute(self, context: ScanContext) -> ScanResult:
        """Run the plugin against the given scan context.

        Args:
            context: Shared scan context containing target and metadata.

        Returns:
            A ``ScanResult`` containing structured findings.
        """

    def setup(self) -> None:
        """Optional hook invoked once before the plugin is first used."""
        return None

    def teardown(self) -> None:
        """Optional hook invoked once when the plugin is unloaded."""
        return None
