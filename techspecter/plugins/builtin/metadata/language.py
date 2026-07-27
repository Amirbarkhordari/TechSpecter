"""Built-in Language Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.language import LanguageAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="language-analyzer-plugin",
    name="Language Analyzer Plugin",
    description="Built-in plugin for passive language analyzer analysis.",
    analyzer_factory=LanguageAnalyzer,
)
