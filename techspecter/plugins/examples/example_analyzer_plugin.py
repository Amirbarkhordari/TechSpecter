"""Example analyzer plugin for plugin developers."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import Analyzer, AnalyzerMetadata
from techspecter.analysis.models.evidence import Evidence
from techspecter.analysis.models.finding import Finding, FindingCategory, Severity
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.core.context import ScanContext
from techspecter.core.interfaces import ScanResult
from techspecter.models.discovery import DiscoveryResult
from techspecter.plugins.developer import metadata_for
from techspecter.plugins.interfaces import AnalyzerPlugin
from techspecter.plugins.metadata import PluginMetadata, PluginType


class ExampleAnalyzer(Analyzer):
    """Minimal example analyzer."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="example-analyzer",
            name="Example Analyzer",
            version="1.0.0",
            description="Demonstrates an analyzer plugin contribution.",
            category=FindingCategory.INFORMATION.value,
        )

    def execute(self, discovery: DiscoveryResult) -> AnalyzerResult:
        finding = Finding(
            id="example:plugin",
            analyzer=self.metadata.id,
            category=FindingCategory.INFORMATION,
            title="Example analyzer plugin",
            description="This finding was produced by the example analyzer plugin.",
            severity=Severity.INFO,
            confidence=10.0,
            evidence=[Evidence(url=str(discovery.target.url))],
        )
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=[finding])


class ExampleAnalyzerPlugin(AnalyzerPlugin):
    """Example plugin that contributes a passive analyzer."""

    @property
    def plugin_metadata(self) -> PluginMetadata:
        return metadata_for(
            "example-analyzer-plugin",
            "Example Analyzer Plugin",
            plugin_type=PluginType.ANALYZER,
            description="Demonstrates analyzer plugin development.",
        )

    def analyzers(self) -> list[Analyzer]:
        return [ExampleAnalyzer()]

    def execute(self, context: ScanContext) -> ScanResult:
        return super().execute(context)


plugin = ExampleAnalyzerPlugin()
