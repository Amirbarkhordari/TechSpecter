"""Built-in Analytics Service Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.analytics_service import AnalyticsServiceAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="analytics-service-analyzer-plugin",
    name="Analytics Service Analyzer Plugin",
    description="Built-in plugin for passive analytics service analyzer analysis.",
    analyzer_factory=AnalyticsServiceAnalyzer,
)
