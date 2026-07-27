"""Built-in Robots.txt Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.robots import RobotsTxtAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="robots-analyzer-plugin",
    name="Robots.txt Analyzer Plugin",
    description="Built-in plugin for passive robots.txt analyzer analysis.",
    analyzer_factory=RobotsTxtAnalyzer,
)
