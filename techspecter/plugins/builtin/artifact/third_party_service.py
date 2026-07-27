"""Built-in Third-Party Service Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.third_party_service import ThirdPartyServiceAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="third-party-service-analyzer-plugin",
    name="Third-Party Service Analyzer Plugin",
    description="Built-in plugin for passive third-party service analyzer analysis.",
    analyzer_factory=ThirdPartyServiceAnalyzer,
)
