"""Built-in Client Configuration Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.client_configuration import ClientConfigurationAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="client-configuration-analyzer-plugin",
    name="Client Configuration Analyzer Plugin",
    description="Built-in plugin for passive client configuration analyzer analysis.",
    analyzer_factory=ClientConfigurationAnalyzer,
)
