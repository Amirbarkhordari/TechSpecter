"""Built-in CDN Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.cdn import CdnAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="cdn-analyzer-plugin",
    name="CDN Analyzer Plugin",
    description="Built-in plugin for passive cdn analyzer analysis.",
    analyzer_factory=CdnAnalyzer,
)
