"""Built-in CORS analyzer plugin."""

from __future__ import annotations

from techspecter.analysis.http.analyzers.cors import CorsAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="cors-analyzer-plugin",
    name="CORS Analyzer Plugin",
    description="Built-in plugin for passive CORS header analysis.",
    analyzer_factory=CorsAnalyzer,
)
