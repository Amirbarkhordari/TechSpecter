"""Built-in HTTP response metadata analyzer plugin."""

from __future__ import annotations

from techspecter.analysis.http.analyzers.response_metadata import HttpResponseMetadataAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="http-response-metadata-analyzer-plugin",
    name="HTTP Response Metadata Analyzer Plugin",
    description="Built-in plugin for passive HTTP response metadata analysis.",
    analyzer_factory=HttpResponseMetadataAnalyzer,
)
