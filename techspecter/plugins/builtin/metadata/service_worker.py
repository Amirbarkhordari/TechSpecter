"""Built-in Service Worker Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.service_worker import ServiceWorkerAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="service-worker-analyzer-plugin",
    name="Service Worker Analyzer Plugin",
    description="Built-in plugin for passive service worker analyzer analysis.",
    analyzer_factory=ServiceWorkerAnalyzer,
)
