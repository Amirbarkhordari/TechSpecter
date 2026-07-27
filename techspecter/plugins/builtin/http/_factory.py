"""Factory helpers for built-in HTTP analyzer plugins."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from techspecter.analysis.analyzers.base import Analyzer
from techspecter.plugins.developer import metadata_for
from techspecter.plugins.interfaces import AnalyzerPlugin
from techspecter.plugins.metadata import PluginMetadata, PluginType

AnalyzerT = TypeVar("AnalyzerT", bound=Analyzer)


def create_analyzer_plugin(
    *,
    plugin_id: str,
    name: str,
    description: str,
    analyzer_factory: Callable[[], AnalyzerT],
) -> AnalyzerPlugin:
    """Create an independent analyzer plugin wrapper."""

    class BuiltinHttpAnalyzerPlugin(AnalyzerPlugin):
        """Built-in HTTP analyzer plugin."""

        @property
        def plugin_metadata(self) -> PluginMetadata:
            return metadata_for(
                plugin_id,
                name,
                plugin_type=PluginType.ANALYZER,
                description=description,
            )

        def analyzers(self) -> list[Analyzer]:
            return [analyzer_factory()]

    return BuiltinHttpAnalyzerPlugin()
