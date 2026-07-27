"""Built-in Apple App Site Association Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.apple_app_site_association import (
    AppleAppSiteAssociationAnalyzer,
)
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="apple-app-site-association-analyzer-plugin",
    name="Apple App Site Association Analyzer Plugin",
    description="Built-in plugin for passive apple app site association analyzer analysis.",
    analyzer_factory=AppleAppSiteAssociationAnalyzer,
)
