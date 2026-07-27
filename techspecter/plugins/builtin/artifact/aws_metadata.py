"""Built-in AWS Metadata Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.aws_metadata import AwsMetadataAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="aws-metadata-analyzer-plugin",
    name="AWS Metadata Analyzer Plugin",
    description="Built-in plugin for passive aws metadata analyzer analysis.",
    analyzer_factory=AwsMetadataAnalyzer,
)
