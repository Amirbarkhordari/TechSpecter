"""Built-in HTML Metadata Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.html_metadata import HtmlMetadataAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="html-metadata-analyzer-plugin",
    name="HTML Metadata Analyzer Plugin",
    description="Built-in plugin for passive html metadata analyzer analysis.",
    analyzer_factory=HtmlMetadataAnalyzer,
)
