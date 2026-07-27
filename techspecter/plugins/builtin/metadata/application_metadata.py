"""Built-in Application Metadata Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.application_metadata import ApplicationMetadataAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="application-metadata-analyzer-plugin",
    name="Application Metadata Analyzer Plugin",
    description="Built-in plugin for passive application metadata analyzer analysis.",
    analyzer_factory=ApplicationMetadataAnalyzer,
)
