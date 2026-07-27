"""Built-in Environment Artifact Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.environment_artifact import EnvironmentArtifactAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="environment-artifact-analyzer-plugin",
    name="Environment Artifact Analyzer Plugin",
    description="Built-in plugin for passive environment artifact analyzer analysis.",
    analyzer_factory=EnvironmentArtifactAnalyzer,
)
