"""Built-in API Key Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.api_key import ApiKeyAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="api-key-analyzer-plugin",
    name="API Key Analyzer Plugin",
    description="Built-in plugin for passive api key analyzer analysis.",
    analyzer_factory=ApiKeyAnalyzer,
)
