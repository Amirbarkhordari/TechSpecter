"""Built-in Monitoring Service Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.monitoring_service import MonitoringServiceAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="monitoring-service-analyzer-plugin",
    name="Monitoring Service Analyzer Plugin",
    description="Built-in plugin for passive monitoring service analyzer analysis.",
    analyzer_factory=MonitoringServiceAnalyzer,
)
