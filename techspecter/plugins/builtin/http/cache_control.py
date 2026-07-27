"""Built-in cache-control analyzer plugin."""

from __future__ import annotations

from techspecter.analysis.http.analyzers.cache_control import CacheControlAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="cache-control-analyzer-plugin",
    name="Cache-Control Analyzer Plugin",
    description="Built-in plugin for passive cache header analysis.",
    analyzer_factory=CacheControlAnalyzer,
)
