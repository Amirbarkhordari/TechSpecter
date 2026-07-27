"""Built-in HTTP header analyzer plugin."""

from __future__ import annotations

from techspecter.analysis.http.analyzers.header import HttpHeaderAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="http-header-analyzer-plugin",
    name="HTTP Header Analyzer Plugin",
    description="Built-in plugin for passive HTTP header analysis.",
    analyzer_factory=HttpHeaderAnalyzer,
)
