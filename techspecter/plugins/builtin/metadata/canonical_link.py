"""Built-in Canonical Link Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.canonical_link import CanonicalLinkAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="canonical-link-analyzer-plugin",
    name="Canonical Link Analyzer Plugin",
    description="Built-in plugin for passive canonical link analyzer analysis.",
    analyzer_factory=CanonicalLinkAnalyzer,
)
