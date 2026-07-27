"""Built-in Manifest Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.manifest import ManifestAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="manifest-analyzer-plugin",
    name="Manifest Analyzer Plugin",
    description="Built-in plugin for passive manifest analyzer analysis.",
    analyzer_factory=ManifestAnalyzer,
)
