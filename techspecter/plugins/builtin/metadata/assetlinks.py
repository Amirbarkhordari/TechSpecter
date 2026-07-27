"""Built-in AssetLinks Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.assetlinks import AssetLinksAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="assetlinks-analyzer-plugin",
    name="AssetLinks Analyzer Plugin",
    description="Built-in plugin for passive assetlinks analyzer analysis.",
    analyzer_factory=AssetLinksAnalyzer,
)
