"""Built-in cookie analyzer plugin."""

from __future__ import annotations

from techspecter.analysis.http.analyzers.cookie import CookieAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="cookie-analyzer-plugin",
    name="Cookie Analyzer Plugin",
    description="Built-in plugin for passive cookie analysis.",
    analyzer_factory=CookieAnalyzer,
)
