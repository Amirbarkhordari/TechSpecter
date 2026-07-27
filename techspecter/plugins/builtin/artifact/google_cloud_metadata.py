"""Built-in Google Cloud Metadata Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.google_cloud_metadata import (
    GoogleCloudMetadataAnalyzer,
)
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="google-cloud-metadata-analyzer-plugin",
    name="Google Cloud Metadata Analyzer Plugin",
    description="Built-in plugin for passive google cloud metadata analyzer analysis.",
    analyzer_factory=GoogleCloudMetadataAnalyzer,
)
