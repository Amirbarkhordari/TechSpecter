"""Built-in OpenAPI Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.openapi import OpenApiAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="openapi-analyzer-plugin",
    name="OpenAPI Analyzer Plugin",
    description="Built-in plugin for passive openapi analyzer analysis.",
    analyzer_factory=OpenApiAnalyzer,
)
