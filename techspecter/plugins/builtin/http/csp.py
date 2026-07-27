"""Built-in CSP analyzer plugin."""

from __future__ import annotations

from techspecter.analysis.http.analyzers.csp import CspAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="csp-analyzer-plugin",
    name="CSP Analyzer Plugin",
    description="Built-in plugin for passive Content-Security-Policy analysis.",
    analyzer_factory=CspAnalyzer,
)
