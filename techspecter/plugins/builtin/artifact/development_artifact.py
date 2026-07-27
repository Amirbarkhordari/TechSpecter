"""Built-in Development Artifact Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.development_artifact import DevelopmentArtifactAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="development-artifact-analyzer-plugin",
    name="Development Artifact Analyzer Plugin",
    description="Built-in plugin for passive development artifact analyzer analysis.",
    analyzer_factory=DevelopmentArtifactAnalyzer,
)
