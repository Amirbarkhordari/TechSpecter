"""Built-in Sitemap Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.sitemap import SitemapAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="sitemap-analyzer-plugin",
    name="Sitemap Analyzer Plugin",
    description="Built-in plugin for passive sitemap analyzer analysis.",
    analyzer_factory=SitemapAnalyzer,
)
