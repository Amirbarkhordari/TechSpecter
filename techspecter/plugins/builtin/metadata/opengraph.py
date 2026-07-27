"""Built-in OpenGraph Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.opengraph import OpenGraphAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="opengraph-analyzer-plugin",
    name="OpenGraph Analyzer Plugin",
    description="Built-in plugin for passive opengraph analyzer analysis.",
    analyzer_factory=OpenGraphAnalyzer,
)
