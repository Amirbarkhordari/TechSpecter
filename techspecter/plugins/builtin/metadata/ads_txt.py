"""Built-in Ads.txt Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.ads_txt import AdsTxtAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="ads-txt-analyzer-plugin",
    name="Ads.txt Analyzer Plugin",
    description="Built-in plugin for passive ads.txt analyzer analysis.",
    analyzer_factory=AdsTxtAnalyzer,
)
