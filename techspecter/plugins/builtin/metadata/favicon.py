"""Built-in Favicon Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.favicon import FaviconAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="favicon-analyzer-plugin",
    name="Favicon Analyzer Plugin",
    description="Built-in plugin for passive favicon analyzer analysis.",
    analyzer_factory=FaviconAnalyzer,
)
