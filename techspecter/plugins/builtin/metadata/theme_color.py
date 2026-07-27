"""Built-in Theme Color Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.theme_color import ThemeColorAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="theme-color-analyzer-plugin",
    name="Theme Color Analyzer Plugin",
    description="Built-in plugin for passive theme color analyzer analysis.",
    analyzer_factory=ThemeColorAnalyzer,
)
