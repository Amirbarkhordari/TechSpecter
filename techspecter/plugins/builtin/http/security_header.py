"""Built-in security header analyzer plugin."""

from __future__ import annotations

from techspecter.analysis.http.analyzers.security_header import SecurityHeaderAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="security-header-analyzer-plugin",
    name="Security Header Analyzer Plugin",
    description="Built-in plugin for passive security header analysis.",
    analyzer_factory=SecurityHeaderAnalyzer,
)
