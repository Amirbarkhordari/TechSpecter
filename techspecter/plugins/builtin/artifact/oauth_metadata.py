"""Built-in OAuth Metadata Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.oauth_metadata import OAuthMetadataAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="oauth-metadata-analyzer-plugin",
    name="OAuth Metadata Analyzer Plugin",
    description="Built-in plugin for passive oauth metadata analyzer analysis.",
    analyzer_factory=OAuthMetadataAnalyzer,
)
