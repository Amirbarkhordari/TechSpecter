"""Example reporter plugin for plugin developers."""

from __future__ import annotations

from techspecter.core.context import ScanContext
from techspecter.core.interfaces import ScanResult
from techspecter.plugins.developer import metadata_for
from techspecter.plugins.interfaces import ReporterPlugin
from techspecter.plugins.metadata import PluginMetadata, PluginType
from techspecter.reporting.engine import ReportEngine


class ExampleReporterPlugin(ReporterPlugin):
    """Example plugin that contributes a report engine."""

    @property
    def plugin_metadata(self) -> PluginMetadata:
        return metadata_for(
            "example-reporter-plugin",
            "Example Reporter Plugin",
            plugin_type=PluginType.REPORTER,
            description="Demonstrates reporter plugin development.",
        )

    def report_engines(self) -> dict[str, ReportEngine]:
        return {"example": ReportEngine(tool_name="ExampleReporter")}

    def execute(self, context: ScanContext) -> ScanResult:
        return super().execute(context)


plugin = ExampleReporterPlugin()
