"""Built-in BrowserConfig Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.browserconfig import BrowserConfigAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="browserconfig-analyzer-plugin",
    name="BrowserConfig Analyzer Plugin",
    description="Built-in plugin for passive browserconfig analyzer analysis.",
    analyzer_factory=BrowserConfigAnalyzer,
)
