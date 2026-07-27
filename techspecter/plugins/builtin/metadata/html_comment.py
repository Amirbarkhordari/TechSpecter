"""Built-in HTML Comment Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.metadata.analyzers.html_comment import HtmlCommentAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="html-comment-analyzer-plugin",
    name="HTML Comment Analyzer Plugin",
    description="Built-in plugin for passive html comment analyzer analysis.",
    analyzer_factory=HtmlCommentAnalyzer,
)
