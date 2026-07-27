"""Built-in redirect analyzer plugin."""

from __future__ import annotations

from techspecter.analysis.http.analyzers.redirect import RedirectAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="redirect-analyzer-plugin",
    name="Redirect Analyzer Plugin",
    description="Built-in plugin for passive redirect chain analysis.",
    analyzer_factory=RedirectAnalyzer,
)
