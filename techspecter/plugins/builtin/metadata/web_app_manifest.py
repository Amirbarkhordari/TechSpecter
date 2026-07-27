"""Built-in Web App Manifest Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.web_app_manifest import WebAppManifestAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="web-app-manifest-analyzer-plugin",
    name="Web App Manifest Analyzer Plugin",
    description="Built-in plugin for passive web app manifest analyzer analysis.",
    analyzer_factory=WebAppManifestAnalyzer,
)
