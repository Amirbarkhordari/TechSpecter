"""Built-in Infrastructure Metadata Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.infrastructure_metadata import (
    InfrastructureMetadataAnalyzer,
)
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="infrastructure-metadata-analyzer-plugin",
    name="Infrastructure Metadata Analyzer Plugin",
    description="Built-in plugin for passive infrastructure metadata analyzer analysis.",
    analyzer_factory=InfrastructureMetadataAnalyzer,
)
