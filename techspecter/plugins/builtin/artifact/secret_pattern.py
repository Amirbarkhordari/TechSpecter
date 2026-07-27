"""Built-in Secret Pattern Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.secret_pattern import SecretPatternAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="secret-pattern-analyzer-plugin",
    name="Secret Pattern Analyzer Plugin",
    description="Built-in plugin for passive secret pattern analyzer analysis.",
    analyzer_factory=SecretPatternAnalyzer,
)
