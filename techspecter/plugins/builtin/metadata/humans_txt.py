"""Built-in Humans.txt Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.humans_txt import HumansTxtAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="humans-txt-analyzer-plugin",
    name="Humans.txt Analyzer Plugin",
    description="Built-in plugin for passive humans.txt analyzer analysis.",
    analyzer_factory=HumansTxtAnalyzer,
)
