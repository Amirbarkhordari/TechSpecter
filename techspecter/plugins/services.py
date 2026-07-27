"""Stable public services exposed through PluginContext."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, cast

from techspecter import __version__

if TYPE_CHECKING:
    from pathlib import Path

    from techspecter.analysis.analyzers.base import Analyzer
    from techspecter.analysis.service import AnalysisService
    from techspecter.configuration.manager import ConfigurationManager
    from techspecter.plugins.hooks import HookRegistry
    from techspecter.plugins.manager import PluginManager
    from techspecter.plugins.registry import PluginRegistry
    from techspecter.reporting.exporters.base import BaseExporter
    from techspecter.reporting.service import ReportService
else:
    from pathlib import Path

    from techspecter.analysis.analyzers.base import Analyzer
    from techspecter.reporting.exporters.base import BaseExporter


class ReadOnlyConfiguration(Protocol):
    """Read-only configuration surface for plugins."""

    @property
    def config(self) -> object:
        """Return the active configuration model."""


class ReadOnlyRegistry(Protocol):
    """Read-only registry surface for plugins."""

    def list(self) -> tuple[str, ...]:
        """Return registered plugin identifiers."""

    def exists(self, name: str) -> bool:
        """Return whether a plugin is registered."""

    def metadata_view(self) -> object:
        """Return immutable plugin metadata."""


class ReadOnlyManager(Protocol):
    """Read-only manager surface for plugins."""

    def collect_analyzers(self) -> list[Analyzer]:
        """Return analyzers contributed by plugins."""

    def collect_exporters(self) -> dict[str, BaseExporter]:
        """Return exporters contributed by plugins."""

    def collect_rule_directories(self) -> list[Path]:
        """Return rule directories contributed by plugins."""


@dataclass(frozen=True, slots=True)
class PluginServices:
    """Stable service facade passed to plugins through PluginContext."""

    version: str
    configuration: ReadOnlyConfiguration
    registry: ReadOnlyRegistry
    manager: ReadOnlyManager
    hooks: HookRegistry
    create_report_service: Callable[[], ReportService]
    create_analysis_service: Callable[[], AnalysisService]

    @classmethod
    def build(
        cls,
        *,
        configuration_manager: ConfigurationManager,
        registry: PluginRegistry,
        manager: PluginManager,
        hooks: HookRegistry,
    ) -> PluginServices:
        """Build plugin services from internal components."""
        from techspecter.analysis.service import AnalysisService
        from techspecter.reporting.service import ReportService

        return cls(
            version=__version__,
            configuration=configuration_manager,
            registry=registry,
            manager=cast("ReadOnlyManager", manager),
            hooks=hooks,
            create_report_service=ReportService,
            create_analysis_service=AnalysisService,
        )
