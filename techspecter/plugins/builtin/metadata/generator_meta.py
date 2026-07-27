"""Built-in Generator Meta Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.generator_meta import GeneratorMetaAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="generator-meta-analyzer-plugin",
    name="Generator Meta Analyzer Plugin",
    description="Built-in plugin for passive generator meta analyzer analysis.",
    analyzer_factory=GeneratorMetaAnalyzer,
)
