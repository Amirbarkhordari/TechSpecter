"""Built-in Firebase Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.firebase import FirebaseAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="firebase-analyzer-plugin",
    name="Firebase Analyzer Plugin",
    description="Built-in plugin for passive firebase analyzer analysis.",
    analyzer_factory=FirebaseAnalyzer,
)
