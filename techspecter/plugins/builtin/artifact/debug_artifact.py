"""Built-in Debug Artifact Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.debug_artifact import DebugArtifactAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="debug-artifact-analyzer-plugin",
    name="Debug Artifact Analyzer Plugin",
    description="Built-in plugin for passive debug artifact analyzer analysis.",
    analyzer_factory=DebugArtifactAnalyzer,
)
