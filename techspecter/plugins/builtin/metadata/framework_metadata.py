"""Built-in Framework Metadata Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.framework_metadata import FrameworkMetadataAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="framework-metadata-analyzer-plugin",
    name="Framework Metadata Analyzer Plugin",
    description="Built-in plugin for passive framework metadata analyzer analysis.",
    analyzer_factory=FrameworkMetadataAnalyzer,
)
