"""Built-in Configuration Artifact Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.configuration_artifact import (
    ConfigurationArtifactAnalyzer,
)
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="configuration-artifact-analyzer-plugin",
    name="Configuration Artifact Analyzer Plugin",
    description="Built-in plugin for passive configuration artifact analyzer analysis.",
    analyzer_factory=ConfigurationArtifactAnalyzer,
)
