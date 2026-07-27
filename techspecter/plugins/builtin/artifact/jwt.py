"""Built-in JWT Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.jwt import JwtAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="jwt-analyzer-plugin",
    name="JWT Analyzer Plugin",
    description="Built-in plugin for passive jwt analyzer analysis.",
    analyzer_factory=JwtAnalyzer,
)
