"""Built-in GraphQL Metadata Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.graphql_metadata import GraphqlMetadataAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="graphql-metadata-analyzer-plugin",
    name="GraphQL Metadata Analyzer Plugin",
    description="Built-in plugin for passive graphql metadata analyzer analysis.",
    analyzer_factory=GraphqlMetadataAnalyzer,
)
