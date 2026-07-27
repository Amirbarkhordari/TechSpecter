"""Built-in content-type analyzer plugin."""

from __future__ import annotations

from techspecter.analysis.http.analyzers.content_type import ContentTypeAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="content-type-analyzer-plugin",
    name="Content-Type Analyzer Plugin",
    description="Built-in plugin for passive content-type analysis.",
    analyzer_factory=ContentTypeAnalyzer,
)
