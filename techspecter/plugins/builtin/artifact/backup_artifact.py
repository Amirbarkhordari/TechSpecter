"""Built-in Backup Artifact Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.backup_artifact import BackupArtifactAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="backup-artifact-analyzer-plugin",
    name="Backup Artifact Analyzer Plugin",
    description="Built-in plugin for passive backup artifact analyzer analysis.",
    analyzer_factory=BackupArtifactAnalyzer,
)
