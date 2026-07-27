"""Built-in Twitter Card Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.twitter_card import TwitterCardAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="twitter-card-analyzer-plugin",
    name="Twitter Card Analyzer Plugin",
    description="Built-in plugin for passive twitter card analyzer analysis.",
    analyzer_factory=TwitterCardAnalyzer,
)
