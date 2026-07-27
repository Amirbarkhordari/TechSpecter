"""Built-in Azure Metadata Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.azure_metadata import AzureMetadataAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="azure-metadata-analyzer-plugin",
    name="Azure Metadata Analyzer Plugin",
    description="Built-in plugin for passive azure metadata analyzer analysis.",
    analyzer_factory=AzureMetadataAnalyzer,
)
