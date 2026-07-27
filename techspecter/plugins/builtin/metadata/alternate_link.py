"""Built-in Alternate Link Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.alternate_link import AlternateLinkAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="alternate-link-analyzer-plugin",
    name="Alternate Link Analyzer Plugin",
    description="Built-in plugin for passive alternate link analyzer analysis.",
    analyzer_factory=AlternateLinkAnalyzer,
)
