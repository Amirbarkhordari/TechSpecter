"""Built-in Source Artifact Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.source_artifact import SourceArtifactAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="source-artifact-analyzer-plugin",
    name="Source Artifact Analyzer Plugin",
    description="Built-in plugin for passive source artifact analyzer analysis.",
    analyzer_factory=SourceArtifactAnalyzer,
)
