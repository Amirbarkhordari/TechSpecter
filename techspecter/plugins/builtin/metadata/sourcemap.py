"""Built-in SourceMap Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.sourcemap import SourceMapAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="sourcemap-analyzer-plugin",
    name="SourceMap Analyzer Plugin",
    description="Built-in plugin for passive sourcemap analyzer analysis.",
    analyzer_factory=SourceMapAnalyzer,
)
