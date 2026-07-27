"""Built-in Security.txt Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.security_txt import SecurityTxtAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="security-txt-analyzer-plugin",
    name="Security.txt Analyzer Plugin",
    description="Built-in plugin for passive security.txt analyzer analysis.",
    analyzer_factory=SecurityTxtAnalyzer,
)
