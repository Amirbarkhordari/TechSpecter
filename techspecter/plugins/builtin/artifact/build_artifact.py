"""Built-in Build Artifact Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.build_artifact import BuildArtifactAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="build-artifact-analyzer-plugin",
    name="Build Artifact Analyzer Plugin",
    description="Built-in plugin for passive build artifact analyzer analysis.",
    analyzer_factory=BuildArtifactAnalyzer,
)
